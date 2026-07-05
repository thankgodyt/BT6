### Title
Peras Certificate Validation Stub Always Returns Success, Enabling Unauthorized Chain Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` method is an unfinished stub that unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. An unprivileged peer can send a crafted `PerasCert` via the object diffusion protocol that boosts any block in the VolatileDB, causing chain selection to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting Peras certificates. The production default instance — which applies to **all** blocks via `instance StandardHash blk => BlockSupportsPeras blk` — implements this as a stub that always returns `Right`:

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

No BLS aggregate signature check, no committee membership check, and no eligibility proof check is performed. The certificate is accepted with the full configured boost weight (`perasWeight params`).

The inbound processing path in `processCerts` calls this `validateCert` callback and, if all certificates pass, adds them to the pool and triggers chain selection:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted.

Once accepted, `chainSelSync` for `ChainSelAddPerasCert` adds the certificate to the `PerasCertDB`, looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock` with the additional Peras weight:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [3](#0-2) 

The Peras weight snapshot used during chain selection is read from the `PerasCertDB`, which now contains the attacker-injected certificate: [4](#0-3) 

**Analogy to the external report:** The external report describes an asymmetric state between two components — L1 can still send messages while L2 is paused and will reject them, with no recovery path. Here the asymmetry is between the validation component (which is in a "stub" state that accepts everything) and the chain selection component (which trusts the validation result and acts on the certificate weight). The validation component's state does not match what chain selection assumes, leading to unauthorized acceptance and irrecoverable chain selection divergence.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that boosts any block currently in the VolatileDB. Because the boost weight is added to the total chain weight used by `preferAnchoredCandidate`, the node may switch to a fork that would otherwise be rejected. This is a **High** chain selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

**High.** Any peer connected via the object diffusion protocol can send crafted certificates. The bypass is unconditional — there is no code path that performs real validation. The TODO comment and linked issue (`#120`) confirm this is a known incomplete implementation shipped in production code.

---

### Recommendation

Implement actual validation in `validatePerasCert` before the Peras protocol is activated on any network:

1. Verify the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)`.
2. Verify each voter's committee membership and eligibility proof (persistent vs. non-persistent VRF output).
3. Verify that the number of voters meets the quorum threshold.
4. Reject certificates whose `pcBoostedBlock` does not correspond to a known block hash.

Until real validation is in place, the object diffusion layer should refuse to relay or accept inbound Peras certificates entirely, rather than accepting them with a no-op validator.

---

### Proof of Concept

1. Connect to a target node via the Peras object diffusion mini-protocol.
2. Construct a `PerasCert` with `pcBoostedBlock` set to the hash of a block on a competing fork currently in the node's VolatileDB, and `pcRoundNo` set to any round not already in the `PerasCertDB`.
3. Send the certificate. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The certificate is added to the `PerasCertDB` with `vpcCertBoost = perasWeight params`.
5. `chainSelSync` looks up the boosted block in the VolatileDB, finds it, and calls `chainSelectionForBlock`.
6. The fork's total weight now exceeds the current chain's weight; the node switches to the fork. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L61-67)
```haskell
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```
