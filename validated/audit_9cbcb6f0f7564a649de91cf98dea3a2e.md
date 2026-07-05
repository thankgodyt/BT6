### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Chain-Selection Manipulation via Unauthorized Certificate Injection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives. Because `processCerts` — the production inbound-certificate handler wired to the ChainDB — relies entirely on this function to gate acceptance, any unprivileged peer can inject an arbitrary Peras certificate for any round number. The `PerasCertDB` deduplicates by `PerasRoundNo`, so the first certificate received for a given round is stored permanently and all subsequent legitimate certificates for that round are silently discarded. The stored bogus certificate then participates in chain selection with a full `perasWeight` boost applied to an attacker-chosen block, and its round number is recorded as `getLatestCertSeen`, corrupting the voting-rule state used by honest nodes.

---

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the mandatory gate for certificate acceptance. The only deployed instance — the universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this function as an unconditional stub:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

This stub is passed directly as the `validateCert` argument in both production pool-writer constructors:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
``` [2](#0-1) 

Inside `processCerts`, certificates not already in the DB are passed to `validateCert`. Because the stub always returns `Right`, the `partitionEithers` branch that would throw `PerasCertValidationError` and disconnect the peer is **never reached**. Every certificate in the batch is accepted and forwarded to `addCert`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [3](#0-2) 

The `PerasCertDB` stores at most one certificate per `PerasRoundNo`. Once a round number is claimed, `implAddCert` returns `PerasCertAlreadyInDB` for any subsequent certificate with the same round:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
``` [4](#0-3) 

The accepted certificate is then used in `chainSelSync` to trigger chain selection for the attacker-chosen `pcCertBoostedBlock`, applying the full `perasWeight` boost:

```haskell
when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ ...
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Additionally, `pcdsLatestCertSeen` is updated to the injected certificate, corrupting the `getLatestCertSeen` value that the Peras voting rules (VR-1A) use to decide whether a node is eligible to vote in the next round.

---

### Impact Explanation

**Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An attacker who connects as a peer and sends a crafted `PerasCert` with:
- `pcCertRound = R` (any target round)
- `pcCertBoostedBlock = <adversarial block point>`

achieves two simultaneous effects:

1. **Round-slot poisoning (analogous to the OUSD zero-address flag):** The attacker's certificate is stored for round R. All subsequent legitimate certificates for round R are silently discarded by the deduplication check. This is the direct analog of the OUSD bug: the zero address was used as a sentinel to block the global upgrade; here, a crafted round number blocks the legitimate certificate for that round.

2. **Chain-selection manipulation:** The stored certificate applies `perasWeight` boost to the attacker-chosen block, potentially causing the node to prefer an adversarial chain over the honest chain. The `getLatestCertSeen` state is also corrupted, which can suppress honest voting in subsequent rounds (VR-1A requires the latest cert seen to be from the previous round).

This falls under the **Critical** impact class: bypass of Peras certificate checks enabling unauthorized certificate acceptance, and **High** impact class: chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is a public network endpoint; any connected peer can submit a batch of `PerasCert` objects. The stub is in the production source tree (not a test or mock), is wired into both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`, and requires no special privileges. The attacker needs only to connect as a peer and send a single crafted certificate before any honest peer sends the legitimate one for that round.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the declared voter set.
- That the voter bitmap references valid committee members for the claimed round.
- That the total stake of the declared voters meets the quorum threshold.

Until the real implementation is available, `processCerts` should reject any certificate whose `pcCertBoostedBlock` does not correspond to a known block in the VolatileDB or ImmutableDB, and should enforce a minimum round-number sanity check (e.g., the round must be within the current or immediately preceding Peras window). This would not close the cryptographic gap but would substantially raise the bar for the chain-selection manipulation vector.

---

### Proof of Concept

1. Connect to a target node as a peer via the object-diffusion mini-protocol.
2. Construct a `PerasCert blk` with:
   - `pcCertRound = PerasRoundNo N` (any round the node has not yet seen a certificate for)
   - `pcCertBoostedBlock = <point of an adversarial block>`
3. Send the certificate in a batch via the object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. `addCert` stores the certificate; `pcdsCertIds` now contains round N.
6. Any subsequent honest certificate for round N is filtered out by `filter (not . Set.member alreadyInDb . getPerasCertRound)`.
7. `chainSelSync` triggers chain selection for the adversarial block with full Peras boost weight, potentially causing the node to switch to the adversarial chain.
8. `getLatestCertSeen` returns the injected certificate, suppressing honest voting in round N+1 (VR-1A fails if the latest cert seen is not from round N-1 relative to the current round).

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L178-179)
```haskell
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L490-531)
```haskell
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```
