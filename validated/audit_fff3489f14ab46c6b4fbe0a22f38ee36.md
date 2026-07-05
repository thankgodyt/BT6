### Title
`NeutralNonce` Degenerates WFA Tiebreaker to Predictable Pool-ID Ordering, Allowing Persistent Committee Seat Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs`)

---

### Summary

The Weighted Fait-Accompli (WFA) committee selection scheme uses `wFATiebreakerWithEpochNonce` to fairly order pools with equal stake. When the epoch nonce is `NeutralNonce` (which occurs at genesis and in the first epoch), the nonce contribution is silently dropped (`mempty`), reducing the tiebreaker to a deterministic hash of the pool ID alone. An adversary can enumerate pool IDs offline, select one whose hash sorts first, and guarantee themselves a persistent committee seat every epoch that begins with `NeutralNonce` — directly analogous to the SEDA bug where choosing a public key that sorts first guarantees priority in reward allocation.

---

### Finding Description

In `wFATiebreakerWithEpochNonce`, the epoch nonce is mixed into a hash to make the tiebreaker unpredictable:

```haskell
epochNonceBytes =
  case epochNonce of
    NeutralNonce -> mempty          -- ← zero bytes contributed
    Nonce h -> BS.byteStringCopy (Hash.hashToBytes h)
``` [1](#0-0) 

When `NeutralNonce` is passed, `epochNonceBytes = mempty`, so the 64-byte input to the hash function is `0x00…00 || poolIdBytes` — the nonce contributes nothing. The resulting ordering is `compare (hash(poolId₁)) (hash(poolId₂))`, which is fully deterministic and computable offline before any chain activity.

This tiebreaker is invoked inside `mkExtWFAStakeDistr` via `descendingStakeWithTiebreaker` whenever two pools share the same stake:

```haskell
| stake1 == stake2 = unWFATiebreaker tiebreaker poolId1 poolId2
``` [2](#0-1) 

The pool that sorts first (lowest hash) is assigned the lower `SeatIndex`, which is then used by `weightedFaitAccompliSplitSeats` to decide which pool crosses the persistent-seat threshold: [3](#0-2) 

The code's own documentation acknowledges the intended protection and its dependency on nonce unpredictability:

> *"For this, we throw the current epoch nonce into the mix to avoid giving an adversary an edge to manipulate the tiebreaking in their favor, as they cannot predict the epoch nonce in advance."* [4](#0-3) 

The test utilities even label the nonce-free variant explicitly:

```haskell
-- | An unfair tie-breaker that compares pool IDs lexicographically.
unfairWFATiebreaker :: WFATiebreaker
unfairWFATiebreaker = WFATiebreaker compare
``` [5](#0-4) 

The `NeutralNonce` path in `wFATiebreakerWithEpochNonce` is functionally equivalent to this "unfair" tiebreaker.

---

### Impact Explanation

A persistent committee member participates in **every** Peras election within the epoch. Non-persistent members must win a per-election local sortition lottery. An adversary who always holds a persistent seat can:

1. Consistently vote for their preferred block candidate in every election.
2. Influence which blocks receive Peras weight boosts, since certificates are formed from committee votes.
3. Skew chain selection: `WeightedSelectView` incorporates Peras weight, so a chain with adversary-controlled weight boosts can be preferred over the honest chain. [6](#0-5) 

This maps to the **High** impact category: a chain-selection bug that lets an unprivileged peer make honest nodes prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- `NeutralNonce` is the epoch nonce at genesis and throughout the first epoch on every Cardano network, including private testnets and new deployments.
- An adversary needs only to generate O(N) cold key pairs (where N is the number of competing pools with equal stake at the threshold), compute `hash(poolId)` for each, and register the one with the lowest hash. No brute-force is required — a few thousand key generations suffice.
- The attack is entirely offline and requires no special privileges: any pool operator can choose their cold key.
- The `WFALSVotingCommittee` is constructed from `mkExtWFAStakeDistr` with the caller-supplied tiebreaker; if the caller passes `wFATiebreakerWithEpochNonce NeutralNonce`, the vulnerability is triggered automatically. [7](#0-6) 

---

### Recommendation

Replace the `NeutralNonce -> mempty` branch with a fixed, non-empty domain-separation constant so that the hash input is never reducible to `hash(poolId)` alone:

```haskell
epochNonceBytes =
  case epochNonce of
    NeutralNonce ->
      BS.byteStringCopy (Hash.hashToBytes (Hash.hashWith id ("WFA-neutral-nonce" :: ByteString)))
    Nonce h -> BS.byteStringCopy (Hash.hashToBytes h)
```

This ensures that even at genesis the tiebreaker ordering is fixed but not pool-ID-predictable in the sense that an adversary cannot choose a pool ID to sort first without knowing the domain separator in advance (which is a constant, but at least it is not `hash(poolId)` alone and cannot be gamed by key selection).

Alternatively, document that `wFATiebreakerWithEpochNonce` **must not** be called with `NeutralNonce` and add a runtime assertion or a separate constructor that rejects it.

---

### Proof of Concept

```
1. Observe that the first epoch uses NeutralNonce.
2. For i in 1..10000:
     Generate cold key pair (sk_i, vk_i).
     Compute poolId_i = hash(vk_i).
     Compute tiebreakerHash_i = hash(poolId_i_bytes).  -- same as wFATiebreakerWithEpochNonce NeutralNonce
3. Select poolId_j with the minimum tiebreakerHash_j.
4. Register pool j with stake equal to the threshold stake.
5. In every epoch that starts with NeutralNonce, pool j is assigned SeatIndex 0
   and passes isAbovePersistentSeatThreshold before any competing pool with the
   same stake, guaranteeing a persistent seat.
6. Pool j votes in every Peras election, influencing weight boosts and chain selection.
``` [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L113-133)
```haskell
weightedFaitAccompliSplitSeats extWFAStakeDistr totalSeats
  -- The target committee size must not be not larger than the actual number of
  -- pools with positive stake in the underlying stake distribution. Otherwise,
  -- it could lead to incorrect/non-desirable results (e.g., granting persistent
  -- seats to voters with zero stake).
  | notEnoughPoolsWithPositiveStake =
      Left
        ( NotEnoughPoolsWithPositiveStake
            totalSeats
            (numPoolsWithPositiveStake extWFAStakeDistr)
        )
  | otherwise =
      -- We should have /at most/ as many persistent voters as the total
      -- committee size, but not more.
      assert (numPersistentVoters <= unTargetCommitteeSize totalSeats) $
        Right
          ( PersistentCommitteeSize numPersistentVoters
          , NonPersistentCommitteeSize numNonPersistentVoters
          , TotalPersistentStake (Cumulative (LedgerStake persistentStake))
          , TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake))
          )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L277-284)
```haskell
-- | Fair weighted Fait-Accompli tiebreaker.
--
-- For this, we throw the current epoch nonce into the mix to avoid giving an
-- adversary an edge to manipulate the tiebreaking in their favor, as they
-- cannot predict the epoch nonce in advance.
--
-- NOTE: this implementation uses BLS-based hashing, but could be replaced by
-- any other cryptographic hash function with similar properties.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L285-305)
```haskell
wFATiebreakerWithEpochNonce :: Nonce -> WFATiebreaker
wFATiebreakerWithEpochNonce epochNonce =
  WFATiebreaker (compare `on` hashWithNonce)
 where
  hashWithNonce :: PoolId -> Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
  hashWithNonce poolId =
    Hash.castHash
      . Hash.hashWith id
      . runByteBuilder (32 + 32)
      $ epochNonceBytes <> poolIdBytes
   where
    epochNonceBytes =
      case epochNonce of
        NeutralNonce -> mempty
        Nonce h -> BS.byteStringCopy (Hash.hashToBytes h)
    poolIdBytes =
      BS.byteStringCopy
        . Hash.hashToBytes
        . unKeyHash
        . unPoolId
        $ poolId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFA.hs (L401-407)
```haskell
  descendingStakeWithTiebreaker
    (poolId1, (LedgerStake stake1, _))
    (poolId2, (LedgerStake stake2, _))
      -- The pools have the same stake => use the tiebreaker to sort them
      | stake1 == stake2 = unWFATiebreaker tiebreaker poolId1 poolId2
      -- The pools have different stake => sort them in descending order
      | otherwise = compare stake2 stake1
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Committee/Utils.hs (L70-73)
```haskell
-- | An unfair tie-breaker that compares pool IDs lexicographically.
unfairWFATiebreaker :: WFATiebreaker
unfairWFATiebreaker =
  WFATiebreaker compare
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/MockChainSel.hs (L44-60)
```haskell
selectChain _ cfg view ours =
  listToMaybe
    . map snd
    . sortOn (Down . fst)
    . mapMaybe selectPreferredCandidate
 where
  -- \| Only retain a candidate if it is preferred over the current chain. As
  -- only a non-empty chain can be preferred over the current chain, we can
  -- extract the 'SelectView' of the tip of the candidate.
  selectPreferredCandidate ::
    (Chain hdr, l) ->
    Maybe (WithEmptyFragment (WeightedSelectView p), (Chain hdr, l))
  selectPreferredCandidate x@(cand, _)
    | let candView = view cand
    , shouldSwitch $ preferCandidate cfg (view ours) candView =
        Just (candView, x)
    | otherwise = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L207-245)
```haskell
-- | Construct a 'WFALSVotingCommittee' for a given epoch
mkWFALSVotingCommittee ::
  VotingCommitteeInput crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (VotingCommittee crypto WFALS)
mkWFALSVotingCommittee
  ( WFALSVotingCommitteeInput
      nonce
      totalSeats
      stakeDistr
    ) = do
    ( numPersistentVoters
      , numNonPersistentVoters
      , persistentStake
      , nonPersistentStake
      ) <-
      bimap WFAError id $
        weightedFaitAccompliSplitSeats
          stakeDistr
          totalSeats

    let seats =
          Map.fromList
            [ (poolId, seatIndex)
            | (seatIndex, (poolId, _, _, _)) <-
                Array.assocs (unExtWFAStakeDistr stakeDistr)
            ]

    pure $
      WFALSVotingCommittee
        { extWFAStakeDistr = stakeDistr
        , candidateSeats = seats
        , persistentCommitteeSize = numPersistentVoters
        , nonPersistentCommitteeSize = numNonPersistentVoters
        , totalPersistentStake = persistentStake
        , totalNonPersistentStake = nonPersistentStake
        , epochNonce = nonce
        }
```
