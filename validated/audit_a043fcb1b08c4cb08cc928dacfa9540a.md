### Title
Unconditional `validatePerasCert` Acceptance Bypasses BLS Aggregate Signature Verification, Enabling Fraudulent Chain Boosting — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. An unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted block hash; the node accepts it, stores it in `PerasCertDB`, and triggers chain selection for the attacker-chosen block. The same instance's `validatePerasVote` checks only stake-distribution membership while skipping vote-signature and VRF-eligibility verification, providing a second path to the same outcome via vote accumulation.

---

### Finding Description

**Root cause — `validatePerasCert`**

`BlockSupportsPeras.hs` contains the following catch-all instance (the only `BlockSupportsPeras` instance in the repository):

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

No aggregate BLS signature is verified, no quorum count is checked, no round-number bounds are enforced, and no boosted-block validity is confirmed. Every structurally well-formed CBOR-encoded `PerasCert` is promoted to a `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**Root cause — `validatePerasVote`**

The same instance's vote validator only looks up the claimed voter ID in the stake distribution:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
```

No vote signature is verified and no VRF eligibility proof is checked. Any peer that knows a valid `PerasVoterId` present in the stake distribution can forge votes for that identity.

**Attacker-controlled entry path**

1. Peer sends a `[PerasCert blk]` batch over the object-diffusion mini-protocol.
2. `processCerts` (in `ObjectPool/PerasCert.hs`) calls `validateCert` — which resolves to `validatePerasCert` — for each certificate not already in the DB.
3. `validatePerasCert` returns `Right` unconditionally.
4. The certificate is timestamped and passed to `addCert`, which stores it in `PerasCertDB`.
5. `chainSelSync` in `ChainSel.hs` receives a `ChainSelAddPerasCert` event, looks up the boosted block in `VolatileDB`, and calls `chainSelectionForBlock` for it.
6. The fraudulent certificate contributes `perasWeight` to the boosted block's `SelectView`, potentially making the attacker's chain preferred over the honest chain.

The same path exists for votes: forged votes accumulate in `PerasVoteDB`, `updatePerasRoundVoteStates` tallies their stake, and once the quorum threshold is crossed a certificate is forged internally and fed back into the same chain-selection path.

---

### Impact Explanation

A single crafted `PerasCert` — requiring only valid CBOR structure, no cryptographic material — can cause an honest node to trigger chain selection for an attacker-chosen block and assign it the full Peras boost weight. If the boosted block is on a competing fork, the node may switch to that fork, violating chain-selection safety. Because the boost is persistent in `PerasCertDB` and survives across chain-selection rounds, the effect is durable until the certificate is garbage-collected. This constitutes a bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer — matching the "Critical: bypass of certificate/vote verification checks" impact category.

---

### Likelihood Explanation

The attack requires only:
- Network connectivity to a target node running the Peras object-diffusion mini-protocol.
- Knowledge of the CBOR serialization format for `PerasCert` (public, defined in `Peras/Cert/V1.hs`).
- A block hash present in the target node's `VolatileDB` (learnable via `ChainSync`).

No stake, no keys, no privileged access, and no brute force are required. The degenerate instance is the only `BlockSupportsPeras` instance in the repository; there is no more-specific Cardano-block override that would restore the missing checks.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Reconstructs the signed message (`roundNo ‖ boostedBlock`) and verifies the aggregate BLS signature against the claimed voter set's aggregate public key.
2. Checks that the number of voters and their combined stake meet the quorum threshold.
3. Validates that each voter's seat index is within the committee bounds for the claimed round.

Replace the stub `validatePerasVote` with an implementation that verifies the per-vote signature (and, for non-persistent members, the VRF eligibility proof) before accepting the vote into the pool.

Until these checks are in place, the object-diffusion endpoints for Peras votes and certificates should not be exposed to untrusted peers on any network where chain-selection integrity is required.

---

### Proof of Concept

1. **Setup**: Run a node with the current codebase. The node has block `B` (hash `H`) in its `VolatileDB` on a minority fork.
2. **Craft certificate**: Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = H`. No valid BLS signature is needed; any 48-byte value satisfies the CBOR decoder.
3. **Send**: Deliver the certificate to the node via the Peras certificate object-diffusion mini-protocol.
4. **Observe**: `processCerts` calls `validatePerasCert`, which returns `Right`. The certificate is stored. `chainSelSync` fires `chainSelectionForBlock` for `B`. The node's `SelectView` for `B`'s chain gains `perasWeight`, and if that tips the comparison, the node switches to the minority fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
