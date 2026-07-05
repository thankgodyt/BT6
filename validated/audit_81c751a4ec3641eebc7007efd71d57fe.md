### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates, Corrupting Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance for all `StandardHash blk` blocks contains a `validatePerasCert` implementation that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural validation. This stub is wired directly into the production inbound certificate processing pipeline (`processCerts` / `makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send a crafted `PerasCert` with an arbitrary boosted-block point, have it accepted as "validated," and cause the receiving node to re-run chain selection with a fraudulent weight boost applied to a minority-fork block, potentially making the node prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional `Right` in the universal instance:** [1](#0-0) 

The comment at line 318 reads `-- TODO: degenerate instance for all blks to get things to compile`. The `validatePerasCert` method of this instance (lines 353–358) ignores every field of the certificate and returns:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No signature check, no quorum check, no committee membership check, no round-number sanity check — nothing. The `PerasValidationErr` data type is itself a stub with a single constructor `PerasValidationErr` and no variants, so there is no error path that can ever be reached.

**Production wiring — the stub is the live validation gate:**

Both production pool writers call `validatePerasCert mkPerasParams` as the sole validation function: [2](#0-1) 

`processCerts` (the inbound handler for peer-supplied certificates) partitions results into `(errors, validCerts)` and adds every cert in `validCerts` to the database: [3](#0-2) 

Because `validatePerasCert` never returns `Left`, the error list is always empty and every inbound certificate is unconditionally accepted.

**Chain selection impact — accepted certs trigger re-selection with a weight boost:**

Once a `ValidatedPerasCert` is accepted, `chainSelSync` adds it to the `PerasCertDB` and immediately triggers chain selection for the boosted block: [4](#0-3) 

Chain selection uses `preferAnchoredCandidate`, which compares `wsvTotalWeight` — the sum of `blockNo` and the accumulated `PerasWeight` boost from all certificates covering blocks in the candidate fragment: [5](#0-4) 

The default `perasWeight` is `PerasWeight 15`: [6](#0-5) 

Each fraudulent certificate adds 15 to the total weight of the fork it targets. An attacker sending `n` certificates for distinct rounds on a minority fork adds `15n` weight, allowing a fork up to `15n` blocks shorter than the honest chain to win chain selection.

---

### Impact Explanation

**Impact category:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

When Peras is enabled, a single connected peer can:
1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block in the node's VolatileDB on a minority fork.
2. Send it via the object diffusion mini-protocol.
3. `processCerts` accepts it unconditionally (no signature, no quorum, no committee check).
4. `chainSelSync` re-runs chain selection; the minority fork now has a `+15` weight advantage per injected certificate.
5. If the honest chain's lead in block count is less than `15n` (for `n` injected certs), the node switches to the attacker's preferred fork.

This constitutes a consensus safety failure: an honest node accepts a chain that the rest of the network has not certified, breaking the common-prefix property that Peras is designed to strengthen.

---

### Likelihood Explanation

Any peer that can establish a connection to the node and participate in the Peras object diffusion mini-protocol can execute this attack with no privileged access, no cryptographic material, and no stake. The only precondition is that Peras is enabled on the target node. The CHANGELOG confirms the chain selection modification is live code: [7](#0-6) 

The attack requires sending a small number of well-formed (but cryptographically unsigned) `PerasCert` CBOR messages, which is trivially achievable by any network peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS/committee signature over the certificate.
2. Checks that the claimed voters form a valid quorum (≥ 3/4 + safety margin of total stake) from the stake distribution at the relevant epoch.
3. Verifies that the boosted block's slot satisfies `perasBlockMinSlots`.
4. Verifies the certificate's round number is consistent with the boosted block's slot.

Until the real implementation is ready, the stub should be replaced with `Left PerasValidationErr` (reject all certificates) rather than `Right` (accept all certificates), so that the Peras certificate diffusion path is safely inert rather than a live bypass.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to a Peras-enabled node.
2. Peer sends a single `PerasCert` CBOR message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of minority-fork block> }
   ```
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }`.
5. `addCert` stores the cert in `PerasCertDB`; `addPerasCertAsync` enqueues a chain selection event.
6. `chainSelSync` runs `chainSelectionForBlock` for the boosted block; `preferAnchoredCandidate` now sees the minority fork with `wsvTotalWeight = blockNo(fork_tip) + 15`.
7. If `blockNo(fork_tip) + 15 > blockNo(honest_tip)`, the node switches to the minority fork.

Repeating step 2 with certificates for additional rounds on the same fork accumulates `+15` per certificate, allowing the attacker to overcome an arbitrarily large honest-chain lead by sending enough certificates. [8](#0-7) [9](#0-8) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```
