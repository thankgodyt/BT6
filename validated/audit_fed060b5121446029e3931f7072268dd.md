### Title
Peras Certificate and Vote Validation Unconditionally Accepts All Inputs — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all production instance `instance StandardHash blk => BlockSupportsPeras blk` implements `validatePerasCert` as an unconditional `Right` (no-op), and `validatePerasVote` with only a stake-distribution lookup and no cryptographic signature check. Any unprivileged peer can submit a crafted `PerasCert` for an arbitrary block and have it accepted with the full `perasWeight` chain-selection boost, or submit votes attributed to any staked voter without possessing that voter's private key.

---

### Finding Description

The `BlockSupportsPeras` type class declares two validation methods:

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

The only concrete instance in the codebase is the catch-all:

```haskell
instance StandardHash blk => BlockSupportsPeras blk
```

Its implementations are stubs that perform no cryptographic verification: [1](#0-0) 

`validatePerasCert` always returns `Right` with the full `perasWeight` boost, regardless of the certificate's content or authenticity: [2](#0-1) 

`validatePerasVote` only checks that the voter ID appears in the stake distribution; it performs no signature verification: [3](#0-2) 

The `stakeAboveThreshold` function used downstream to gate certificate forging also carries an explicit TODO noting that `PerasVoteStake` and the quorum threshold may not be in the same units, meaning the quorum check itself may be comparing incommensurable values: [4](#0-3) 

The `ValidatedPerasCert` produced by the stub carries a `vpcCertBoost` equal to `perasWeight params`, which is the value used directly in chain selection to boost the certified block: [5](#0-4) 

The `votesReachQuorum` smart constructor, which gates certificate forging, calls `stakeAboveThreshold` with the accumulated `PerasVoteStake` values — values that are accepted without signature verification from `validatePerasVote`: [6](#0-5) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer that can submit Peras protocol messages can:

1. Craft a `PerasCert` for any block of their choosing (e.g., a minority fork tip).
2. Submit it to a node. `validatePerasCert` returns `Right` unconditionally, producing a `ValidatedPerasCert` with the full `perasWeight` boost.
3. The boosted block is now preferred in chain selection over honest chains of equal or slightly greater length, because the Peras weight is added on top of block count.

Similarly, for votes: a peer can submit `PerasVote` messages attributed to any staked voter ID without possessing that voter's private key. `validatePerasVote` accepts the vote as long as the voter ID appears in the stake distribution. Enough such votes accumulate to trigger `votesReachQuorum`, forging a certificate for an adversarially chosen block.

Both paths result in an honest node applying an illegitimate chain-selection boost to an adversarially chosen block, causing it to diverge from the canonical chain.

---

### Likelihood Explanation

**Medium.** The Peras protocol integration is in active development (the TODO comments reference open issues). However, the stub instance is a catch-all over `StandardHash blk` — the broadest possible constraint — meaning it applies to every block type including `CardanoBlock`. Any code path that calls `validatePerasCert` or `validatePerasVote` on a received network message reaches this stub. The attack requires only the ability to send Peras protocol messages to a node, which is available to any peer.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the claimed voter set, using the same `implVerifyCert` logic already implemented in `WFALS.hs` and `EveryoneVotes.hs`.
2. Replace the stub `validatePerasVote` with a real implementation that verifies the vote's cryptographic signature before accepting it.
3. Resolve the unit-mismatch TODO in `stakeAboveThreshold`: either normalize `PerasVoteStake` to a relative value before comparison, or change the function signature to accept the total stake distribution and perform normalization internally.
4. Remove or gate the catch-all `instance StandardHash blk => BlockSupportsPeras blk` so that it cannot be silently used for production block types once real implementations exist.

---

### Proof of Concept

**Crafted-certificate attack path:**

```
Attacker peer  →  sends PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarial_block }
Node calls     →  validatePerasCert params cert
                  -- stub: always returns Right (ValidatedPerasCert cert perasWeight)
Chain selection →  adversarial_block receives +perasWeight boost
                  -- node now prefers adversarial fork over honest chain of equal length
```

**Crafted-vote attack path:**

```
Attacker peer  →  sends PerasVote { pvVoteRound = r, pvVoteBlock = adversarial_block,
                                     pvVoteVoterId = any_staked_voter_id }
Node calls     →  validatePerasVote params stakeDistr vote
                  -- stub: lookupPerasVoteStake succeeds (voter ID is in distribution)
                  -- returns Right (ValidatedPerasVote vote stake) with NO sig check
Aggregation    →  vote stake accumulates toward quorum threshold
                  -- once threshold crossed, forgePerasCert produces ValidatedPerasCert
                  -- with full perasWeight boost for adversarial_block
```

The relevant stub code is at: [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-272)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```
