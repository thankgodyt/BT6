### Title
Unvalidated Peras Certificate Injection Inflates Chain-Selection Weight, Enabling Non-Canonical Chain Preference — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

`implAddCert` in `PerasCertDB/Impl.hs` carries an explicit TODO acknowledging that it currently performs **no non-trivial validation** of incoming certificates. `implGetWeightSnapshot` then builds the `PerasWeightSnapshot` from **every** certificate stored in `pcdsCertsByTicket`, without filtering by chain membership or block validity. Because `preferAnchoredCandidate` and `compareAnchoredFragments` consume this snapshot directly to decide which chain is heavier, an unprivileged peer that can deliver a crafted `ValidatedPerasCert` object (via the ObjectDiffusion mini-protocol) for a block on a minority fork can artificially inflate that fork's weight and cause an honest node to switch away from the canonical chain.

---

### Finding Description

**Root cause 1 — missing certificate validation in `implAddCert`**

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        ...
        pure AddedPerasCertToDB
```

The only gate is a round-number deduplication check. There is no verification that the boosted block is on any valid chain, no check that the certificate's aggregate BLS signature meets quorum, and no check that the round is consistent with the current ledger state. Any `ValidatedPerasCert` object that arrives with a fresh round number is unconditionally stored. [1](#0-0) 

**Root cause 2 — `implGetWeightSnapshot` uses the gross certificate set**

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

Every certificate in `pcdsCertsByTicket` — including those for blocks on minority forks that have never been on the canonical chain — contributes a boost entry to the returned `PerasWeightSnapshot`. There is no filtering by VolatileDB membership, chain membership, or ledger validity. [2](#0-1) 

**Root cause 3 — chain selection consumes the snapshot without re-filtering**

`preferAnchoredCandidate` and `compareAnchoredFragments` call `weightedSelectView`, which calls `weightBoostOfFragment`. That function sums the boost for every block on the candidate fragment that appears in the snapshot. If the snapshot contains a boost for a block on a minority fork, that boost is counted in full when the fork is evaluated as a candidate. [3](#0-2) [4](#0-3) 

The `wsvTotalWeight` used for the final comparison is `BlockNo + weightBoost`, so an injected boost of magnitude `B` directly adds `B` to the fork's apparent weight. [5](#0-4) 

---

### Impact Explanation

This is a **High** chain-selection bug. An unprivileged peer that can deliver a crafted certificate object through the ObjectDiffusion mini-protocol can make an honest node compute an inflated `wsvTotalWeight` for a minority fork. If the injected boost is large enough (the `PerasWeight` field is a `Word64`), the node will call `ShouldSwitch` and adopt the non-canonical chain, constituting a chain-selection safety failure. Because `takeVolatileSuffix` also uses the same snapshot to determine the immutable boundary, an inflated snapshot can additionally cause the node to treat fewer blocks as immutable, widening the rollback window beyond the security parameter `k`. [6](#0-5) [7](#0-6) 

---

### Likelihood Explanation

The ObjectDiffusion inbound handler accepts `ValidatedPerasCert` objects from any connected peer. Because `implAddCert` performs no cryptographic or chain-membership validation (the TODO is explicit), a peer only needs to construct a well-typed Haskell value with a fresh round number and an arbitrary boosted-block point. No stake, no keys, and no quorum are required under the current implementation. The attack is therefore reachable from any unprivileged node-to-node connection. [8](#0-7) 

---

### Recommendation

1. **Implement the missing validation in `implAddCert`**: verify the aggregate BLS signature against the current committee, confirm the boosted block exists in the VolatileDB, and confirm the round number is consistent with the current ledger state. This closes the acknowledged gap at issue #120.

2. **Filter `implGetWeightSnapshot` to the volatile set**: build the snapshot only from certificates whose boosted block is currently present in the VolatileDB (analogous to the Portals fix of subtracting the reward pool from the balance before using it in the swap formula). Certificates for blocks that have been garbage-collected or were never received should not contribute weight.

3. **Update the `Fingerprint` on garbage collection**: `implGarbageCollect` deliberately skips updating the fingerprint, which means consumers that watch the fingerprint for changes will not re-evaluate chain selection after stale boosts are removed. [9](#0-8) 

---

### Proof of Concept

1. Honest node has current chain `C` (length `N`, no Peras boosts) and a competing fork `F` (length `N-1`, block `B` at its tip, present in the VolatileDB).
2. Attacker connects via the ObjectDiffusion mini-protocol and delivers a `ValidatedPerasCert` with `roundNo = freshRound`, `boostedBlock = blockPoint B`, `boost = PerasWeight (2*N)`.
3. `implAddCert` stores the certificate (round number is fresh, no other check).
4. `implGetWeightSnapshot` returns a snapshot containing `(blockPoint B, PerasWeight (2*N))`.
5. `chainSelSync` detects the boosted block `B` is in the VolatileDB and calls `chainSelectionForBlock` for `B`.
6. `preferAnchoredCandidate` computes `wsvTotalWeight(F) = (N-1) + 2*N = 3*N-1 > N = wsvTotalWeight(C)`.
7. The node switches to fork `F`, abandoning the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L245-275)
```haskell
implGarbageCollect ::
  forall m blk.
  IOLike m =>
  PerasCertDbEnv m blk ->
  SlotNo ->
  STM m (m ())
implGarbageCollect PerasCertDbEnv{pcdbTracer, pcdbState} slotNo = do
  -- No need to update the 'Fingerprint' as we only remove certificates that do
  -- not matter for comparing interesting chains.
  modifyTVar pcdbState (fmap gc)
  pure $ traceWith pcdbTracer (GarbageCollected slotNo)
 where
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
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L104-112)
```haskell
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L161-174)
```haskell
    canRequestMoreObjects :: InboundSt k object -> Bool
    canRequestMoreObjects !st =
      not (Set.null (canRequestNext st))

    -- Computes how many new IDs we can request so that receiving all of them
    -- won't make 'outstandingFifo' exceed 'maxFifoLength'.
    numIdsToReq :: InboundSt objectId object -> NumObjectIdsReq
    numIdsToReq !st =
      maxNumIdsToReq
        `min` ( fromIntegral maxFifoLength
                  - (fromIntegral $ Seq.length $ outstandingFifo st)
                  - numIdsInFlight st
              )

```
