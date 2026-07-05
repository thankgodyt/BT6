I found the exact analog. Let me verify the full `processVotes` and `processCerts` code before writing the final report.### Title
Malicious Peer Poisons a Vote/Cert Batch to Suppress Valid Peras Votes, Blocking Certificate Formation and Disrupting Weighted Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs` and `PerasCert.hs`)

---

### Summary

`processVotes` and `processCerts` implement an all-or-nothing batch policy: if **any single** item in a peer-supplied batch fails validation, the **entire batch** is thrown away. An unprivileged peer can exploit this by bundling one crafted invalid vote (or certificate) together with many valid votes (or certificates) from honest committee members. All valid items in the batch are silently discarded. Because Peras weight boosts are derived from certificates that are themselves derived from quorum-reaching vote aggregation, suppressing enough votes prevents quorum, prevents certificate formation, and removes the Peras weight boost from chain selection — potentially causing an honest node to prefer a non-canonical, less-secure chain over the correctly-boosted canonical one.

---

### Finding Description

`processVotes` in `PerasVote.hs` collects validation results for every vote in the batch, then branches on `partitionEithers`:

```haskell
case partitionEithers validationResults of
  ([], validatedVotes) ->
    mapM_ (addVote . WithArrivalTime now) validatedVotes
  (errs, _) ->
    throw (PerasVoteValidationError errs)   -- entire batch dropped
```

The `(errs, _)` branch discards the `_` component — the valid votes — entirely. The same pattern appears verbatim in `processCerts`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)   -- entire batch dropped
```

The code comment in both files explicitly acknowledges the design choice and flags it as potentially revisable:

> *"This assumes that cert/vote validation is cheap, which may not be true in practice … Hence we may revisit this to lazily abort validation upon the first error encountered."*

The comment focuses on performance, but the security consequence — that one bad item silently kills all good items — is not addressed.

The Peras weight boost is a first-class input to chain selection. `preferAnchoredCandidate` in `AnchoredFragment.hs` takes a `PerasWeightSnapshot` and, when it is non-empty, compares chains by `wsvTotalWeight = blockNo + weightBoost`. A chain that carries a Peras certificate boost can be preferred over a strictly longer chain without one. Suppressing the votes that would have produced that certificate therefore directly affects which chain the node selects. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Peras certificates provide a `wsvWeightBoost` that is added to `wsvBlockNo` to form `wsvTotalWeight`, the primary chain-order key. A chain carrying a valid Peras certificate can therefore be preferred over a longer chain that lacks one. If an adversary suppresses the votes that would have reached quorum for a given round, no certificate is forged for that round, the `PerasWeightSnapshot` for the boosted block is never populated, and `preferAnchoredCandidate` falls back to pure block-number comparison. An adversarial fork that is shorter but would have lost under weighted comparison can now win. This is a **chain selection bug** — the node adopts a non-canonical chain — not merely a liveness issue. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

Any node that participates in the object-diffusion mini-protocol for Peras votes/certs is reachable. An adversary needs only to:

1. Connect to the target node as a standard peer (no special privilege required).
2. Collect valid votes from honest committee members via the same diffusion network.
3. Craft one syntactically well-formed but semantically invalid vote (e.g., wrong stake lookup, wrong round, or a vote whose `PerasVoteId` is not in the DB but whose `validatePerasVote` returns `Left PerasValidationErr`).
4. Bundle it with the collected valid votes in a single `opwAddObjects` call.

The `processVotes` call site (`makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB`) passes the entire peer-supplied list directly to `processVotes` without pre-filtering. The adversary does not need stake, keys, or any privileged position. [7](#0-6) [8](#0-7) 

---

### Recommendation

Replace the all-or-nothing batch policy with a per-item policy: process each vote/certificate independently, add the valid ones, and only disconnect from (or penalise) the peer for the invalid ones. The `partitionEithers` result already separates valid from invalid items; the fix is to use both halves:

```haskell
-- Instead of throwing on any error:
case partitionEithers validationResults of
  ([], validatedVotes) -> mapM_ (addVote . WithArrivalTime now) validatedVotes
  (errs, validVotes)   -> do
    mapM_ (addVote . WithArrivalTime now) validVotes   -- keep the good ones
    throw (PerasVoteValidationError errs)              -- still punish the peer
```

The same change applies to `processCerts`. This mirrors the pull-based, per-item approach already used for blocks in `chainSelection` / `validateCandidate`, where a valid prefix of an otherwise-invalid candidate is preserved rather than discarded. [9](#0-8) 

---

### Proof of Concept

```
Adversary (peer A)                         Target node
─────────────────────────────────────────────────────
1. Connect via object-diffusion protocol
2. Observe honest votes V1..Vn diffused
   for round R (all valid, targeting block B)
3. Craft one invalid vote Vbad
   (e.g., voter ID not in stake distribution)
4. Send batch [V1, V2, ..., Vn, Vbad]
   via opwAddObjects
                                           5. processVotes called with [V1..Vn, Vbad]
                                           6. mapM validateVote → [Right v1..Right vn, Left err]
                                           7. partitionEithers → errs=[err], valid=[v1..vn]
                                           8. Branch: (errs, _) → throw PerasVoteValidationError
                                              ALL of V1..Vn are discarded
                                           9. Quorum for round R never reached
                                          10. No certificate forged for block B
                                          11. PerasWeightSnapshot not updated for B
                                          12. preferAnchoredCandidate uses blockNo only
                                          13. Adversary's fork (same length, no boost needed)
                                              is now equally or more preferred → chain switch
```

The attack is repeatable every Peras round. If the adversary can consistently poison the vote batch for a target block, the Peras weight boost is permanently suppressed for that block, and the adversary's fork wins chain selection on block-number alone. [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-117)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-68)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L44-61)
```haskell
-- | Data structure for tracking the weight of blocks due to Peras boosts.
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight
  }
  deriving stock Eq
  deriving Generic
  deriving newtype NoThunks

instance StandardHash blk => Show (PerasWeightSnapshot blk) where
  show = show . perasWeightSnapshotToList

-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty

-- | Create a weight snapshot from a list of boosted points with an associated
-- weight. In case of duplicate points, their weights are combined.
--
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1165-1184)
```haskell
          ValidPrefix candidate' -> do
            whenJust mTentativeHeader clearTentativeHeader
            -- Prefix of the candidate because it contained rejected blocks
            -- (invalid blocks). Note that the
            -- spec says go back to candidate selection,
            -- because there might still be some candidates that contain the
            -- same rejected block. To simplify the control flow, we do it
            -- differently: instead of recomputing the candidates taking
            -- rejected blocks into account, we just truncate the remaining
            -- candidates that contain rejected blocks.
            candidates1 <- truncateRejectedBlocks candidates0
            -- Only include the prefix if it is still preferred over the current
            -- chain. When the candidate is now empty because of the truncation,
            -- it will be dropped here, as it will not be preferred over the
            -- current chain.
            let newReason = preferAnchoredCandidate bcfg weights curChain (Diff.getSuffix candidate')
            let candidates2 = case newReason of
                  ShouldSwitch reason' -> (candidate', reason') : candidates1
                  ShouldNotSwitch{} -> candidates1
            go (sortCandidates candidates2)
```
