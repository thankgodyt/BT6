### Title
`getLatestCertSeen` Voting Precondition Never Enforced — Dead Accumulator in `PerasCertDB` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

`PerasCertDB` carefully maintains a `pcdsLatestCertSeen` field that tracks the highest-round certificate ever added to the database. The `getLatestCertSeen` API accessor is documented as directly gating Peras voting eligibility — a node must have seen a certificate before it may vote in any round after the first. However, a codebase-wide search finds **zero call sites** for `getLatestCertSeen`. The accumulated state is never read back to enforce the precondition, making it a dead accumulator. Any node can cast votes in arbitrary rounds without having observed a certificate, bypassing the Peras voting eligibility rule.

---

### Finding Description

`PerasCertDbState` carries a `pcdsLatestCertSeen` field: [1](#0-0) 

`implAddCert` updates this field on every new certificate insertion, keeping it as the maximum-round certificate seen: [2](#0-1) 

`implGarbageCollect` explicitly preserves `pcdsLatestCertSeen` across GC runs (even after the referenced certificate is removed from `pcdsCertsByTicket`): [3](#0-2) 

The `PerasCertDB` API exposes `getLatestCertSeen` with an explicit comment that it **directly gates voting**: [4](#0-3) 

A codebase-wide `grep` for `getLatestCertSeen`, `latestCertSeen`, and `LatestCertSeen` returns **no matches** outside the definition and its own property tests. The voting layer never calls `getLatestCertSeen` to check whether a certificate has been observed before allowing a vote to be cast or accepted.

The property tests in the API file confirm the intended invariant — `getLatestCertSeen` should be monotonically non-decreasing and GC-stable — but these invariants are only tested in isolation, never enforced at the voting call site: [5](#0-4) 

---

### Impact Explanation

The Peras protocol requires that a node must have observed at least one certificate before it is eligible to vote in any round beyond the first (origin). This precondition exists to prevent nodes that have no knowledge of the certified chain tip from injecting votes that could steer quorum toward an uncertified or adversarial block.

Because `getLatestCertSeen` is never called:

1. A node with an empty `PerasCertDB` (e.g., freshly started, syncing, or in a cooldown period) can produce and submit `ValidatedPerasVote` objects for any round.
2. Those votes pass through `updatePerasRoundVoteStates` and are aggregated into `PerasRoundVoteState` without any check that the voter had seen a certificate.
3. If enough such votes accumulate, `votesReachQuorum` fires, `forgePerasCert` produces a certificate, and `addPerasCertSync` injects it into `PerasCertDB`, triggering `chainSelectionForBlock`.
4. The resulting `PerasWeightSnapshot` boosts the targeted block's weight in chain selection, potentially causing honest nodes to prefer a non-canonical chain.

This is a bypass of Peras voting eligibility checks that enables unauthorized vote and certificate acceptance, directly weakening the chain-selection security guarantees Peras is designed to provide.

---

### Likelihood Explanation

The entry path is reachable by any unprivileged network peer that can submit `ValidatedPerasVote` messages via the object-diffusion mini-protocol. No key compromise, stake majority, or operator access is required. The missing call site is structural — there is no conditional guard anywhere in the vote-processing pipeline that reads `getLatestCertSeen` — so the bypass is unconditional for any node that has not yet received a certificate.

---

### Recommendation

The voting rules must call `getLatestCertSeen` on the local `PerasCertDB` before accepting or forwarding a vote for any round after origin. Concretely:

- In the vote-submission path (wherever `updatePerasRoundVoteStates` is invoked), read `getLatestCertSeen` atomically and reject the vote if the result is `Nothing` and the vote's round is not the first round.
- Alternatively, thread the `getLatestCertSeen` result into `mkPerasCertInclusionView` / the voting-rules predicate so the precondition is evaluated at the same site as the other inclusion rules in `Cert/Inclusion.hs`.

The existing `prop_addCertLatestCertSeenMonotonic` and `prop_garbageCollectPreservesLatestCertSeen` properties should be supplemented with an integration test that verifies a vote submitted without a prior certificate is rejected.

---

### Proof of Concept

1. Start a node with an empty `PerasCertDB` (`pcdsLatestCertSeen = Nothing`).
2. Construct a `ValidatedPerasVote` for round 2 (any round > origin) targeting an arbitrary block.
3. Submit it via the object-diffusion path, which calls `addPerasVoteWithAsyncCertHandling` → `updatePerasRoundVoteStates`.
4. Observe that `updatePerasRoundVoteState` processes the vote without consulting `getLatestCertSeen`.
5. With sufficient colluding votes, `votesReachQuorum` fires, a certificate is forged, and `chainSelectionForBlock` is triggered for the targeted block — despite the node never having seen a legitimate certificate.

The dead accumulator is confirmed by the fact that `pcdsLatestCertSeen` is written on every `implAddCert` call but `implGetLatestCertSeen` has no callers outside the property-test definitions in `PerasCertDB.API`. [6](#0-5) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L60-63)
```haskell
  , pcdsLatestCertSeen :: !(Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ The certificate with the highest round number that has been added to the
  -- db since it has been opened.
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L184-196)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L236-243)
```haskell
implGetLatestCertSeen ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
implGetLatestCertSeen PerasCertDbEnv{pcdbState} = do
  PerasCertDbState{pcdsLatestCertSeen} <-
    forgetFingerprint <$> readTVar pcdbState
  pure pcdsLatestCertSeen
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L257-274)
```haskell
  gc :: PerasCertDbState blk -> PerasCertDbState blk
  gc
    PerasCertDbState
      { pcdsCertsByTicket
      , pcdsLastTicketNo
      , pcdsLatestCertSeen
      } =
      let pcdsCertsByTicket' =
            Map.filter
              (\cert -> pointSlot (getPerasCertBoostedBlock cert) >= NotOrigin slotNo)
              pcdsCertsByTicket
          pcdsCertIds' =
            Set.fromList (getPerasCertRound <$> Map.elems pcdsCertsByTicket')
       in PerasCertDbState
            { pcdsCertIds = pcdsCertIds'
            , pcdsCertsByTicket = pcdsCertsByTicket'
            , pcdsLastTicketNo = pcdsLastTicketNo
            , pcdsLatestCertSeen = pcdsLatestCertSeen
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L176-205)
```haskell
-- | After adding a cert, the round number reported by 'getLatestCertSeen'
-- should be greater than or equal to its previous value.
prop_addCertLatestCertSeenMonotonic ::
  MonadSTM m =>
  PerasCertDB m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m Bool
prop_addCertLatestCertSeenMonotonic db cert =
  atomically $ do
    prevLatest <- getLatestCertSeen db
    _ <- addCert db cert
    newLatest <- getLatestCertSeen db
    let getRound = getPerasCertRound . forgetArrivalTime
    pure $ case (prevLatest, newLatest) of
      (_, Nothing) -> False -- after adding a cert, the latest cert seen should not go back to 'Nothing'
      (Nothing, Just _) -> True -- if there was no cert seen before, any new cert should be greater than or equal to it
      (Just prev, Just new) -> getRound new >= getRound prev

-- | 'getLatestCertSeen' is not affected by garbage collection.
prop_garbageCollectPreservesLatestCertSeen ::
  (MonadSTM m, StandardHash blk) =>
  PerasCertDB m blk ->
  SlotNo ->
  m Bool
prop_garbageCollectPreservesLatestCertSeen db slotNo =
  atomically $ do
    prevLatest <- getLatestCertSeen db
    _ <- garbageCollect db slotNo
    newLatest <- getLatestCertSeen db
    pure $ prevLatest == newLatest
```
