### Title
Peras Certificate Validation Stub Always Accepts Any Certificate, Enabling Unauthorized Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no BLS aggregate signature verification, no voter eligibility check, and no quorum proof. Any unprivileged peer can submit a crafted Peras certificate over the network; the node will accept it as fully validated and apply its weight boost to the targeted chain during chain selection, potentially causing the node to prefer an adversarial or non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must verify a Peras certificate before it can influence chain selection. The only instance in the codebase is a universal stub:

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

This instance applies to **all** block types (it is the only instance). No BLS aggregate signature over `(roundNo, boostedBlock)` is verified, no voter bitmap is checked against the committee, and no quorum threshold is enforced at the certificate level. The function simply wraps the raw, unverified `PerasCert` in a `ValidatedPerasCert` and assigns it the full configured weight boost.

The resulting `ValidatedPerasCert` is then fed directly into `addPerasCertAsync`, which enqueues it for chain selection:

```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
``` [2](#0-1) 

Chain selection then uses `WeightedSelectView`, where `wsvWeightBoost` from the accepted certificate is added to `wsvBlockNo` to compute `wsvTotalWeight`, which is the primary comparator:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [3](#0-2) 

```haskell
preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ ...)
      ...
``` [4](#0-3) 

A forged certificate claiming to boost an adversarial block will therefore cause `wsvTotalWeight` of the adversarial chain to exceed that of the honest chain, and `preferCandidate` will return `ShouldSwitch`, causing the node to adopt the adversarial chain.

The same pattern applies to `validatePerasVote`: it only checks whether the voter ID appears in the stake distribution map, but performs no cryptographic signature verification over the vote content:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [5](#0-4) 

An attacker who knows any eligible voter ID (which is public, derived from the stake distribution) can forge votes for arbitrary blocks and rounds, accumulate them to quorum via `updatePerasRoundVoteStates`, and trigger `addPerasCertAsync` with a forged certificate — all without holding any private key. [6](#0-5) 

---

### Impact Explanation

**Critical — bypass of Peras certificate/vote signature validation enabling unauthorized chain weight manipulation and chain selection divergence.**

An unprivileged peer can:
1. Craft a `PerasCert` for any block and any round with no valid BLS aggregate signature.
2. Submit it via the Peras miniprotocol; `validatePerasCert` accepts it unconditionally.
3. The certificate is enqueued and applied as a weight boost to the targeted chain.
4. `preferCandidate` switches the node to the adversarial chain because its `wsvTotalWeight` now exceeds the honest chain's weight.

This is a direct bypass of the Peras quorum and BLS signature requirements, allowing a single adversarial peer to unilaterally boost any chain and cause honest nodes to diverge from the canonical chain — a consensus safety failure.

---

### Likelihood Explanation

**High.** The attack requires only network access to a node running Peras-enabled code. No stake, no private keys, and no operator compromise are needed. The attacker only needs to know a valid voter ID from the public stake distribution (trivially observable on-chain) to forge votes, or can submit a bare `PerasCert` directly. The stub is the only instance in the codebase and applies universally to all block types.

---

### Recommendation

1. Implement real BLS aggregate signature verification in `validatePerasCert`, checking the aggregate signature against the claimed voter set and the message `hash(roundNo || boostedBlock)`.
2. Implement real per-vote signature verification in `validatePerasVote`, verifying the individual BLS signature against the voter's registered key before accepting the vote.
3. Until real validation is implemented, gate the Peras miniprotocol handler so that certificate and vote submission is rejected at the network boundary (e.g., return a protocol error or disconnect) rather than forwarding unverified objects into chain selection.
4. Add a property-based test asserting that `validatePerasCert` rejects certificates with invalid or missing signatures.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer (no stake, no keys)
  │
  │  submits PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlock }
  │  (no valid BLS signature required)
  ▼
validatePerasCert params cert
  = Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
  -- SupportsPeras.hs:353-358: always Right, no verification
  ▼
addPerasCertAsync cdb (WithArrivalTime t validatedCert)
  -- ChainSel.hs:303-310: enqueues to cdbChainSelQueue
  ▼
chainSelSync processes ChainSelAddPerasCert
  ▼
weightedSelectView computes wsvWeightBoost for adversarialChain
  wsvTotalWeight adversarialChain = blockNo + perasWeight  -- boosted
  wsvTotalWeight honestChain      = blockNo + 0            -- unboosted
  ▼
preferCandidate: wsvTotalWeight adversarial > wsvTotalWeight honest
  → ShouldSwitch → node adopts adversarial chain
``` [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
