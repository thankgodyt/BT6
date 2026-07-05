### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This stub is wired directly into the live Peras certificate diffusion pipeline (`makePerasCertPoolWriterFromChainDB`), which feeds accepted certificates into `addPerasCertAsync` → `chainSelSync` → `chainSelectionForBlock`. Any unprivileged peer can craft a `PerasCert` for an arbitrary block, submit it over the Peras certificate mini-protocol, and cause the receiving node to treat that block as Peras-boosted and re-run chain selection in its favour.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote validation. Its only production instance is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` defined in `SupportsPeras.hs`. The `validatePerasCert` method of that instance is:

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

No signature is verified, no committee membership is checked, no round-number bounds are enforced. Every `PerasCert` value, regardless of origin or content, is wrapped in `ValidatedPerasCert` and returned as valid.

This function is called unconditionally in the production certificate diffusion writer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← stub always returns Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

`processCerts` filters out already-known round numbers, calls `validateCert` on the remainder, and on success passes each result to `addCert`. Because `validatePerasCert` never fails, the filter is the only gate: [3](#0-2) 

The accepted certificate is then enqueued via `addPerasCertAsync`, which routes it to `chainSelSync (ChainSelAddPerasCert ...)`. That handler adds the cert to `PerasCertDB` and, if the boosted block is in the VolatileDB, immediately calls `chainSelectionForBlock`: [4](#0-3) 

The `PerasCertDB.addCert` deduplication check (`Set.member roundNo pcdsCertIds`) only prevents the same *round number* from being added twice; it does not compensate for the absent cryptographic check: [5](#0-4) 

The `ValidatedPerasCert` wrapper is the type-level promise that validation occurred. Because `validatePerasCert` manufactures that wrapper unconditionally, the type system's safety guarantee is voided.

---

### Impact Explanation

**Critical — Bypass of Peras certificate verification enabling unauthorized chain selection manipulation.**

An attacker who controls a single peer connection can:

1. Craft a `PerasCert` naming any block hash and any round number.
2. Deliver it via the Peras certificate diffusion mini-protocol.
3. The node accepts it as `ValidatedPerasCert` with full `perasWeight` boost.
4. `chainSelectionForBlock` is triggered for the attacker's chosen block.
5. If the attacker's fork block is present in the VolatileDB (e.g., previously diffused), the node may switch to that fork.

Because Peras weight boosts are additive to chain density in chain selection, a single forged certificate can make a shorter fork outweigh the honest chain, causing the node to permanently diverge from the canonical chain. This is a consensus safety failure reachable by an unprivileged peer with no stake.

---

### Likelihood Explanation

**High.** The Peras certificate diffusion infrastructure is fully wired into the production `ChainDB` pipeline. The `makePerasCertPoolWriterFromChainDB` writer is the live inbound handler for peer-supplied certificates. No special privileges, keys, or stake are required — any peer that can open a connection and speak the Peras object-diffusion mini-protocol can trigger this path. The crafted certificate requires only a valid CBOR encoding of `PerasCert` (round number + block point), both of which are public information.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion pipeline is enabled in any environment reachable by untrusted peers. Validation must include at minimum:

1. **Aggregate signature verification** — confirm the certificate carries a valid aggregate BLS/KES signature from a quorum of the elected committee for the stated round.
2. **Committee membership check** — verify the signers were eligible for the stated round using the stake snapshot at the relevant epoch boundary.
3. **Round-number bounds** — reject certificates for rounds that are too far in the past or future relative to the current slot.
4. **Boosted-block existence** — optionally, reject certificates whose boosted block point is not on any known chain.

Until real validation is in place, the certificate diffusion writer should either be disabled or gated behind a feature flag that is off by default in production builds.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → Peras cert mini-protocol
     → makePerasCertPoolWriterFromChainDB.opwAddObjects
     → processCerts [...] (validatePerasCert mkPerasParams) [...]
     → validatePerasCert: Right (ValidatedPerasCert { vpcCertBoost = perasWeight })
     → addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
     → chainSelSync (ChainSelAddPerasCert cert varProcessed)
     → PerasCertDB.addCert  [dedup by round only, no crypto check]
     → chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**Concrete scenario (private testnet):**

1. Honest node A is on chain `C` (tip at block `B_honest`).
2. Attacker node E has previously diffused a fork block `B_fork` to A (it sits in A's VolatileDB).
3. E sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B_fork) }` to A.
4. A's `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = W }` without any check.
5. `chainSelSync` calls `chainSelectionForBlock` for `B_fork`.
6. Chain selection now sees `B_fork`'s chain as having weight `density(B_fork_chain) + W`.
7. If `W` is large enough (it equals `perasWeight params`, a protocol-level constant), A switches to E's fork.
8. A is now on a non-canonical chain, diverging from the honest network. [6](#0-5) [2](#0-1) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
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
```
