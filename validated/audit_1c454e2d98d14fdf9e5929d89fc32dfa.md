### Title
Peras Certificate Validation Stub Always Accepts Peer-Supplied Certificates Without Cryptographic Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate received from a peer, performing no cryptographic or structural validation. An unprivileged remote peer can craft and diffuse arbitrary Peras certificates that boost any block, causing the receiving node to apply an unearned weight boost during chain selection and potentially prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` and `validatePerasVote` as the gatekeepers for all inbound Peras objects received over the network. The default instance — which is the only instance in the codebase and applies to all block types via `instance StandardHash blk => BlockSupportsPeras blk` — implements `validatePerasCert` as a stub that unconditionally returns `Right`:

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

This stub is called directly in the inbound certificate processing pipeline. `processCerts` in `PerasCert.hs` calls `validatePerasCert mkPerasParams` on every certificate received from a peer before adding it to the `PerasCertDB`: [2](#0-1) 

Once a `ValidatedPerasCert` is in the `PerasCertDB`, `chainSelSync` uses it to trigger chain selection for the boosted block: [3](#0-2) 

The weight snapshot from `PerasCertDB` is then used during chain selection comparisons to give the boosted block extra weight. A peer-supplied certificate that passes the no-op validator will cause the node to treat an arbitrary block as having a Peras weight boost of `perasWeight params`.

Similarly, `validatePerasVote` only checks whether the voter ID appears in the stake distribution map, but performs no signature or eligibility proof verification:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [4](#0-3) 

Any peer who knows a valid voter ID (which is public on-chain stake pool data) can forge votes for any block and any round, accumulating enough fake stake to trigger certificate forging internally.

---

### Impact Explanation

This matches the **High** impact category: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

A peer with no stake and no cryptographic credentials can:
1. Send a crafted `PerasCert` boosting a block on a minority or adversarial fork.
2. The certificate passes `validatePerasCert` unconditionally.
3. The certificate is stored in `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block.
4. The boosted block receives `perasWeight params` extra weight in chain selection comparisons.
5. If the adversarial fork's boosted weight exceeds the honest chain's weight, the node switches to the adversarial fork.

The `vpcCertBoost` field is set to `perasWeight params` — a protocol-level constant — meaning the attacker receives the maximum possible boost for free.

---

### Likelihood Explanation

The Peras certificate and vote diffusion infrastructure is wired into the production `ChainDB` API (`addPerasCertAsync`, `addPerasVoteWithAsyncCertHandling`) and the `ObjectPool` diffusion layer. Any peer connected via the Peras object diffusion mini-protocol can send certificates. The attacker needs only a network connection to the target node; no stake, keys, or privileged access are required. [5](#0-4) 

---

### Recommendation

Replace the stub with real validation before the Peras diffusion mini-protocol is enabled in production. At minimum, `validatePerasCert` must verify:
- The certificate's cryptographic signature against the committee's aggregate key.
- That the round number is within the valid window.
- That the boosted block point is structurally valid.

`validatePerasVote` must verify the voter's VRF/eligibility proof, not merely check stake-distribution membership. The tracked issue (`https://github.com/tweag/cardano-peras/issues/120`) should be resolved before the Peras diffusion layer is activated on any network where chain selection integrity is required.

---

### Proof of Concept

1. Connect to a target node that has the Peras cert diffusion mini-protocol active.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on an adversarial fork>`.
3. Send it via the object diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The cert is added to `PerasCertDB`; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. The adversarial fork's tip now has `perasWeight params` extra weight; if this exceeds the honest chain's weight advantage, the node switches forks. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-459)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
      PerasCertTicketNo ->
      STM m (Map PerasCertTicketNo (m (WithArrivalTime (ValidatedPerasCert blk))))
  -- ^ Get all known Peras certs with a ticket number strictly greater than the
  -- given one, in ascending order. The values are 'm' actions to allow
  -- implementations with on-disk storage.
  , getPerasCertIds :: STM m (Set PerasRoundNo)
  -- ^ Get the set of all Peras certificate round numbers currently in the
  -- database.
  , addPerasVoteWithAsyncCertHandling ::
      WithArrivalTime (ValidatedPerasVote blk) ->
      m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
  -- ^ Add a Peras vote to the vote database, returning the result of the
  -- vote addition. If a certificate is produced in the process (quorum
  -- reached), it will be added via 'addPerasCertAsync' under the hood, in
  -- which case the corresponding promise will be returned.
```
