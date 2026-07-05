### Title
Peras Certificate and Vote Validation Unconditionally Succeeds — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` provides stub implementations of `validatePerasCert` and `validatePerasVote` that skip all actual cryptographic and semantic validation. `validatePerasCert` unconditionally returns `Right` (success) for any certificate, and `validatePerasVote` skips signature verification entirely. This is the direct analog to the commented-out `deadline` parameter in the original report: a required validation step is explicitly omitted, causing the system to accept inputs it should reject.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, a universal overlapping instance is declared for all `StandardHash blk`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Within this instance, `validatePerasCert` is implemented as:

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
``` [2](#0-1) 

This unconditionally returns `Right` — every certificate, regardless of content or cryptographic validity, is accepted and assigned a full `perasWeight` boost.

Similarly, `validatePerasVote` skips all cryptographic signature verification and only checks stake distribution membership:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

Any vote claiming to be from a stake pool ID that appears in the distribution is accepted without verifying the BLS or other cryptographic signature that should prove the voter controls that pool's key.

The `BlockSupportsPeras` type class explicitly requires these functions to perform real validation:

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
``` [4](#0-3) 

The `stakeAboveThreshold` function used downstream in `votesReachQuorum` correctly checks quorum, but it operates on already-"validated" votes whose stake values were accepted without signature verification: [5](#0-4) 

---

### Impact Explanation

**Critical / High.** Peras certificates carry a `PerasWeight` boost that directly influences chain selection. A `ValidatedPerasCert` returned by `validatePerasCert` is used to assign weight to a block during chain comparison. Because `validatePerasCert` always returns `Right`, any peer can inject a certificate referencing an arbitrary block, causing an honest node to assign a weight boost to a non-canonical or adversary-controlled chain. This is a bypass of Peras certificate validation that enables unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: bypass of certificate/vote verification checks" and "High: chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

For votes: because `validatePerasVote` skips signature verification, an attacker who knows any stake pool ID in the distribution can forge votes for that pool without possessing its private key. Enough forged votes can satisfy `votesReachQuorum`, producing a `ValidatedPerasVotesWithQuorum` that drives `forgePerasCert` to create a certificate boosting an adversary-chosen block.

---

### Likelihood Explanation

The object diffusion inbound path (`Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.Inbound`) receives Peras votes and certificates from unprivileged network peers and calls `validatePerasCert` / `validatePerasVote` on them. No operator privilege or key compromise is required. Any peer connected to the node can send a crafted certificate or vote message. The universal instance applies to all block types for which no more specific instance exists, which includes the current Cardano instantiation given no override is present in the searched production files.

---

### Recommendation

Replace the stub implementations with real cryptographic validation before the Peras object diffusion protocol is active on any network. At minimum, gate the universal instance behind a compile-time flag or newtype wrapper so it cannot silently apply to production block types. The `validatePerasCert` function must verify the certificate's BLS aggregate signature against the claimed voter set, and `validatePerasVote` must verify the individual voter's signature before accepting the vote as valid.

---

### Proof of Concept

1. Connect an unprivileged peer to a node running the Peras object diffusion protocol.
2. Craft a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = p` pointing to an adversary-controlled block `p`.
3. Send it via the Peras certificate diffusion miniprotocol.
4. The node calls `validatePerasCert params cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The certificate is stored and the weight boost is applied to block `p` during chain selection, causing the node to prefer the adversary's chain over the honest canonical chain.

For the vote path: craft `PerasVote` records claiming to be from stake pool IDs visible in the public stake distribution (no private key needed). Submit enough votes to satisfy `votesReachQuorum`. The node accepts them all via `validatePerasVote` (no signature check), constructs a `ValidatedPerasVotesWithQuorum`, and `forgePerasCert` produces a certificate boosting the adversary's target block. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
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
