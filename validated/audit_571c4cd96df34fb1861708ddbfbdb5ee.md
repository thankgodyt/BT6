### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Peras Certificate, Enabling Fraudulent Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` universal instance's `validatePerasCert` is an acknowledged stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or committee-membership checks. This function is wired directly into the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`). When Peras is enabled, any unprivileged peer can inject an arbitrary `PerasCert` (any round number, any boosted block point) that will pass "validation", be stored in the `PerasCertDB`, and trigger chain selection with a fraudulent weight boost, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation always succeeds**

The `BlockSupportsPeras` instance for all `StandardHash blk` is explicitly marked as a degenerate placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

Every certificate, regardless of its content, is wrapped in `Right ValidatedPerasCert` and assigned the full configured `perasWeight`. No signature, committee membership, round validity, or boosted-block existence check is performed.

**Production inbound pipeline wires this stub directly**

`makePerasCertPoolWriterFromChainDB` — the production writer used when Peras is enabled — passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

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

`processCerts` calls `validateCert` on each inbound certificate and, if all pass (which they always do), forwards them to `addCert`: [3](#0-2) 

**Chain selection consumes the fraudulent weight**

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then compares candidates using `preferAnchoredCandidate`, which incorporates the `PerasWeightSnapshot` — now containing the fraudulent boost: [5](#0-4) 

The `WeightedSelectView` comparison adds `wsvWeightBoost` to `wsvBlockNo` to compute total weight, so a fake certificate with a large configured `perasWeight` can make a shorter candidate chain outweigh the honest current chain: [6](#0-5) 

---

### Impact Explanation

**Impact: High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

When Peras is enabled via `rnFeatureFlags`, a malicious peer connected via the object-diffusion mini-protocol can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block in the node's VolatileDB (a block on a minority or adversarial fork).
2. Send it to the target node. `validatePerasCert` unconditionally accepts it.
3. The certificate is stored in `PerasCertDB` and chain selection is triggered for the boosted block.
4. The candidate chain containing the boosted block now has `perasWeight` additional weight units added to its `wsvWeightBoost`.
5. If the fraudulent boost is sufficient, the node switches away from the honest canonical chain to the adversarial fork.

This constitutes a **chain selection safety failure**: an unprivileged peer can cause an honest node to adopt a non-canonical chain without any stake majority or cryptographic key compromise.

---

### Likelihood Explanation

**Likelihood: Medium** (conditional on Peras being enabled).

- Peras is currently disabled by default (`rnFeatureFlags`), limiting exposure to nodes that explicitly opt in.
- However, the code is in production files, the object-diffusion mini-protocol is reachable from any connected peer, and the attack requires only sending a well-formed CBOR-encoded `PerasCert` — no privileged keys or stake are needed.
- The TODO comments explicitly acknowledge the missing validation (referencing issue #120), confirming this is a known incomplete state shipped in production code.

---

### Recommendation

1. **Block inbound certificates until real validation is implemented.** Until `validatePerasCert` performs actual cryptographic and committee-membership checks, the inbound pipeline should reject all externally received certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.
2. **Gate the object-diffusion writer on Peras being fully implemented**, not merely enabled via a feature flag.
3. **Implement the full `validatePerasCert`** per the Peras CIP-0140 specification: verify the aggregate BLS signature over the certificate, confirm the signers are eligible committee members for the given round, and confirm the boosted block exists and is within the valid round window.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion mini-protocol
     → makePerasCertPoolWriterFromChainDB.opwAddObjects
     → processCerts [...] (validatePerasCert mkPerasParams) [...]
     → validatePerasCert: always returns Right ValidatedPerasCert
     → ChainDB.addPerasCertAsync cert
     → chainSelSync: PerasCertDB.addCert + chainSelectionForBlock
     → preferAnchoredCandidate uses PerasWeightSnapshot with fraudulent boost
     → node switches to adversarial fork
```

**Crafted certificate:** Any `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` where `p` is the point of a block on a candidate fork present in the node's VolatileDB. The certificate requires no valid signature because `validatePerasCert` never checks one. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
