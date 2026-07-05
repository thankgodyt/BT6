### Title
Unconditional `validatePerasCert` Acceptance Allows Unprivileged Peer to Manipulate Peras Chain Selection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in `BlockSupportsPeras.hs` unconditionally accepts every inbound Peras certificate without performing any cryptographic verification, committee-membership check, or round-validity check. An unprivileged peer can craft a `PerasCert` that names any block already in the node's VolatileDB as the boosted block, have it accepted as a `ValidatedPerasCert`, and thereby inject artificial Peras weight into chain selection — potentially causing the node to prefer a minority fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`**

The production `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

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

No check is performed on:
- the cryptographic aggregate signature over the committee votes,
- whether the claimed voters form a quorum of the committee,
- whether `pcCertRound` is a valid round for the current epoch, or
- whether `pcCertBoostedBlock` is a block the node has actually validated.

**The `ValidatedPerasCert` wrapper is the only gate**

`addPerasCertAsync` in the `ChainDB` API accepts only a `WithArrivalTime (ValidatedPerasCert blk)`: [2](#0-1) 

The sole way to produce a `ValidatedPerasCert` is through `validatePerasCert`. Because that function always returns `Right`, any raw `PerasCert` received over the network is immediately promoted to a `ValidatedPerasCert` and stored.

**Cert diffusion is wired into the production node**

The node-to-node handler set in `NodeToNode.hs` includes both `hPerasCertDiffusionClient` and `hPerasCertDiffusionServer`, and the codec set includes `cPerasCertDiffusionCodec`: [3](#0-2) 

This mirrors the vote diffusion path (`makePerasVotePoolWriterFromChainDB`) where inbound objects are validated before being stored: [4](#0-3) 

**Chain selection is triggered by the stored cert**

`chainSelSync` in `ChainSel.hs` processes every stored cert: it looks up the `pcCertBoostedBlock` in the VolatileDB and, if found, calls `chainSelectionForBlock` with the boosted header, adding `perasWeight params` to that block's `PerasWeightSnapshot`: [5](#0-4) 

The `weightedSelectView` function then uses this snapshot to compute `wsvWeightBoost`, which is added to `wsvBlockNo` to form `wsvTotalWeight` — the quantity used to decide whether to switch forks: [6](#0-5) 

**Analog to the BakerFi whitelist bypass**

In BakerFi, `onlyWhiteListed` guards the *caller* of `deposit`/`mint`, but the *receiver* of the shares is never checked — allowing a non-whitelisted address to accumulate shares and later redeem them. Here, `validatePerasVote` partially guards the *voter* (stake-distribution lookup), but `validatePerasCert` does not guard the *certificate itself* (no signature, no committee quorum, no round check) — allowing any peer to inject a fake boost for any block it chooses as the "receiver" of the weight. [7](#0-6) 

---

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

When Peras is enabled, an attacker who is a normal peer can:

1. Learn a block hash from the target node's VolatileDB via ChainSync (no privilege required).
2. Craft a `PerasCert` naming that block as `pcCertBoostedBlock` with an arbitrary `pcCertRound`.
3. Send it over the Peras cert diffusion mini-protocol.
4. `validatePerasCert` accepts it unconditionally; `addPerasCertAsync` stores it.
5. `chainSelSync` triggers chain selection for the boosted block, adding `perasWeight params` to its total weight.
6. The node may switch to a minority fork that it would otherwise have rejected.

This violates the Peras chain-selection security invariant: only blocks that have received a genuine quorum of committee votes should receive a weight boost.

---

### Likelihood Explanation

**Medium.** Peras is not enabled by default (the CHANGELOG notes "if Peras is disabled (which is the default), there is no observable difference"), so the attack surface is limited to nodes that have explicitly enabled Peras. However, once Peras is enabled, the attack requires only a standard peer connection and knowledge of a block hash — both trivially obtainable — with no cryptographic material or stake required.

---

### Recommendation

Replace the stub implementation of `validatePerasCert` with real validation that checks:

1. **Aggregate BLS signature**: verify the aggregate signature in the certificate against the claimed set of committee members' public keys.
2. **Committee quorum**: confirm the claimed voters form a quorum (total stake above `perasQuorumStakeThreshold`) using the stake distribution for the relevant epoch.
3. **Round validity**: confirm `pcCertRound` falls within the valid range for the current epoch and has not already been superseded.
4. **Boosted block existence and validity**: confirm `pcCertBoostedBlock` refers to a block the node has header-validated.

The existing `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert` in the `Committee` subsystem already implement the correct pattern for aggregate-signature and membership verification and should be wired into `validatePerasCert`. [8](#0-7) 

---

### Proof of Concept

```
1. Connect to a target node (Peras-enabled) as an ordinary peer.
2. Via ChainSync, obtain the hash H of a block B on a minority fork
   that is present in the target node's VolatileDB.
3. Construct:
     PerasCert { pcCertRound    = <any round number>
               , pcCertBoostedBlock = BlockPoint <slot of B> H }
4. Send this PerasCert over the Peras cert diffusion mini-protocol.
5. The target node calls validatePerasCert, which returns Right unconditionally.
6. addPerasCertAsync stores the ValidatedPerasCert.
7. chainSelSync looks up B in the VolatileDB, finds it, and calls
   chainSelectionForBlock with the boosted header.
8. weightBoostOfPoint now returns perasWeight params for B's point.
9. wsvTotalWeight for any fragment containing B is inflated by perasWeight params.
10. preferAnchoredCandidate may now return ShouldSwitch for the minority fork,
    causing the node to roll back to and adopt the attacker-chosen chain.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-303)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L436-437)
```haskell
  , cPerasCertDiffusionCodec :: Codec (PerasCertDiffusion blk) e m bPCD
  , cPerasVoteDiffusionCodec :: Codec (PerasVoteDiffusion blk) e m bPVD
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-494)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```
