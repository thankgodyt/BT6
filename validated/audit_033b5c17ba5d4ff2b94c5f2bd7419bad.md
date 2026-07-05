### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates Without Cryptographic or Committee Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every inbound `PerasCert`, performing zero cryptographic, committee-membership, or round-validity checks. This function is wired directly into the live certificate-ingest path (`makePerasCertPoolWriterFromChainDB`) that processes certificates received from remote peers over the ObjectDiffusion mini-protocol. An unprivileged peer can therefore inject arbitrary, fully fabricated Peras certificates that are accepted without any authorization, boosting attacker-chosen blocks and corrupting chain selection.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate that must authorize a raw `PerasCert` before it may enter the node's state:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance (covering all `StandardHash blk`, i.e., every production block type) implements this as:

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

No signature is verified, no committee membership is checked, no round bounds are enforced, and no boosted-block existence is confirmed. Every certificate, regardless of content or origin, is wrapped in `ValidatedPerasCert` and returned as `Right`.

This stub is called directly in the production certificate-ingest pipeline. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every new certificate and, when all pass (which they always do), forwards each to `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

`ChainDB.addPerasCertAsync` then feeds the certificate into `chainSelSync`, which uses the certificate's boost weight to potentially switch the node's selected chain: [4](#0-3) 

The `PerasCertDB` stores the certificate and updates the `PerasWeightSnapshot` used by chain selection, meaning the fabricated boost is durable within the node's volatile state: [5](#0-4) 

---

### Impact Explanation

**Critical. Bypass of Peras certificate validation that enables unauthorized certificate acceptance.**

A remote peer can craft a `PerasCert` naming any `(PerasRoundNo, Point blk)` pair — including a block on a weaker or adversarial fork — and send it over the ObjectDiffusion mini-protocol. The node will:

1. Accept the certificate unconditionally (no signature, no committee check).
2. Store it in `PerasCertDB`, updating the `PerasWeightSnapshot`.
3. Trigger chain selection, which may now prefer the attacker's fork because it carries a fabricated Peras boost.

Because Peras certificates are the mechanism by which the protocol achieves fast finality and chain-quality guarantees, accepting forged certificates directly undermines the chain-selection invariants that Peras is designed to enforce. An honest node can be made to prefer a non-canonical chain without the attacker controlling any stake or keys.

---

### Likelihood Explanation

**High.** The vulnerable code path is active in the production node whenever the ObjectDiffusion mini-protocol for Peras certificates is enabled. No special privileges are required: any peer that can establish a connection and speak the ObjectDiffusion protocol can send crafted certificates. The only natural barrier is the deduplication check (`certsNotAlreadyInDb`), which only prevents re-injection of a certificate for a round already seen — it does not prevent injection of a certificate for a new round.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that performs, at minimum:

1. **Committee membership check**: verify the certificate's signers are eligible committee members for the given round (using the epoch nonce and stake distribution).
2. **Aggregate signature verification**: verify the BLS aggregate signature over `(roundNo, boostedBlock)` against the aggregate public key of the claimed committee members.
3. **Round bounds check**: verify the certificate's round number is within the acceptable window relative to the current chain tip.
4. **Boosted-block existence check**: verify the boosted block point refers to a block that is plausibly on a recent chain (within the volatile window).

The `WFALS` committee module already contains the cryptographic primitives needed (aggregate signature verification, VRF output verification): [6](#0-5) 

Until a real implementation is in place, the certificate ingest path should be disabled or gated behind a feature flag to prevent production exposure.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to an honest node as a peer.
2. Attacker sends a `PerasCert` via the ObjectDiffusion mini-protocol with:
   - `pcCertRound = <any new round number>`
   - `pcCertBoostedBlock = <point of a block on attacker's fork>`
3. The node's `makePerasCertPoolWriterFromChainDB` receives the certificate batch.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{..}`.
5. `ChainDB.addPerasCertAsync` is called with the fabricated `ValidatedPerasCert`.
6. `chainSelSync` processes the certificate: if the boosted block is on a candidate chain, the node may switch to that chain.

**Root cause (single line):**

```haskell
validatePerasCert params cert = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [7](#0-6) 

No attacker capability beyond network connectivity is required.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-562)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```
