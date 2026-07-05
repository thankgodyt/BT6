### Title
Stub `validatePerasCert` Always Accepts Any Crafted Peras Certificate, Enabling Fraudulent Chain-Weight Inflation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or quorum checks. An unprivileged peer can therefore send a crafted `PerasCert` that boosts any block on an adversarial fork, inflating that fork's Peras weight and causing an honest node to switch away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's aggregate BLS signature, quorum stake, round number, and boosted-block identity before the certificate is allowed to influence chain selection. The only concrete instance in the codebase is a universal stub:

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

Every certificate, regardless of content, is accepted and assigned the full `perasWeight params` boost. The `PerasCertDB.implAddCert` implementation carries a matching TODO acknowledging that non-trivial validation logic is still absent: [2](#0-1) 

The inbound certificate pipeline in `processCerts` calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

A certificate that passes this non-check is handed to `ChainDB.addPerasCertAsync`, which triggers `chainSelSync` → `chainSelectionForBlock`. Chain selection then computes `wsvTotalWeight` as `blockNo + weightBoostOfFragment`, where `weightBoostOfFragment` sums the fraudulent boost from the injected certificate: [4](#0-3) [5](#0-4) 

The `preferCandidate` comparison then switches to the adversarial chain if its inflated total weight exceeds the honest chain's weight: [6](#0-5) 

A proper BLS-based `implVerifyCert` exists in the `EveryoneVotes` committee module and performs aggregate-signature verification, membership checks, and stake validation, but it is **not wired into** the `validatePerasCert` path used by the inbound diffusion layer: [7](#0-6) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Construct a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork.
2. Send it over the object-diffusion mini-protocol.
3. `validatePerasCert` returns `Right` unconditionally; the certificate is stored in `PerasCertDB`.
4. Chain selection fires; the adversarial fork's `wsvTotalWeight` is inflated by `perasWeight params` (a large configurable value, e.g. 15 on mainnet-like parameters).
5. The honest node switches to the adversarial chain, abandoning the canonical chain.

This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of Ouroboros Peras.

The `SecurityParam` reinterpretation for Peras means the rollback budget is also expressed in weight units, so a single fraudulent certificate can push a block past the immutability threshold, causing durable acceptance of the wrong ledger state: [8](#0-7) 

---

### Likelihood Explanation

**Medium** when Peras is enabled. Peras is currently an experimental feature disabled by default per the CHANGELOG:

> "Note that if Peras is disabled (which is the default), there is no observable difference." [9](#0-8) 

However, the feature flag exists and the full certificate-diffusion pipeline is compiled and active when enabled. Any peer connected to a Peras-enabled node can exploit this with a single malformed message. No stake, keys, or operator access is required.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the declared voter set, using the same `implVerifyCert` logic already present in `EveryoneVotes`.
2. Checks that the total stake of the declared voters meets the quorum threshold (`stakeAboveThreshold`).
3. Validates that `pcCertRound` is within the acceptable window relative to the current slot.
4. Validates that `pcCertBoostedBlock` refers to a known, non-genesis block.

Until this is done, Peras should remain disabled in any deployment where an adversarial peer can reach the node.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  sends PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlock }
  │  over object-diffusion mini-protocol
  ▼
processCerts
  └─ validatePerasCert mkPerasParams cert
       → always Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })
  └─ ChainDB.addPerasCertAsync cert
       ▼
chainSelSync (ChainSelAddPerasCert)
  └─ PerasCertDB.addCert  ← stored without any cryptographic check
  └─ chainSelectionForBlock adversarialBlock
       ▼
weightedSelectView
  └─ wsvTotalWeight = blockNo(adversarialTip)
                    + weightBoostOfFragment snap adversarialFrag
                    -- snap now contains fraudulent boost for adversarialBlock
  └─ preferCandidate: adversarialWeight > honestWeight → ShouldSwitch
       ▼
Honest node switches to adversarial chain  ← consensus safety failure
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-44)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
  deriving (Eq, Generic, NoThunks, ToCBOR, FromCBOR)
  deriving Show via Quiet SecurityParam

-- | The maximum amount of weight we can roll back.
maxRollbackWeight :: SecurityParam -> PerasWeight
maxRollbackWeight = PerasWeight . unNonZero . maxRollbacks
```

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```
