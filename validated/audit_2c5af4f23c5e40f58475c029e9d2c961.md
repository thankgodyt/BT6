### Title
Forged Peras Votes Accepted Due to Missing Signature Verification in `validatePerasVote` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasVote` function checks only that a vote's voter ID exists in the stake distribution, but never verifies the vote's cryptographic signature. An unprivileged peer can forge votes attributed to any legitimate stakepool in the distribution. These forged votes pass the validation gate, accumulate toward quorum, and can be used to forge a `ValidatedPerasCert` that boosts an attacker-chosen block, corrupting chain selection on every honest node that processes them.

### Finding Description

`validatePerasVote` is the production implementation used for all block types via the default instance:

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
``` [1](#0-0) 

The check is structurally identical to the beacon-kit flaw: a property of the vote that can be read from a public source (the stake distribution) is verified, while the property that actually binds the vote to its claimed author (the BLS signature) is never checked. The `_params` argument is discarded entirely, and no call to any signature-verification primitive appears in the function body.

The entry path is the object-diffusion mini-protocol. Inbound votes from any peer are routed through `processVotes`, which calls `validatePerasVote` as its sole gate:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) 

A vote that passes this check is wrapped in `ValidatedPerasVote` and stored. Once enough forged votes accumulate above the quorum threshold, `votesReachQuorum` returns a `ValidatedPerasVotesWithQuorum`:

```haskell
votesReachQuorum cfg votes =
  ...
  | not votesHaveEnoughStake -> Nothing
  | otherwise -> Just ValidatedPerasVotesWithQuorum { ... }
``` [3](#0-2) 

That value is then passed to `forgePerasCert`, which produces a `ValidatedPerasCert` boosting the attacker's chosen block. The companion `validatePerasCert` default instance compounds the problem by accepting every certificate unconditionally:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [4](#0-3) 

Certificates received from peers are processed by `processCerts`, which also uses this stub as its sole validator:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [5](#0-4) 

### Impact Explanation

Peras certificates boost blocks in chain selection. A node that accepts a forged certificate for an attacker-chosen block will assign it a `vpcCertBoost` weight and may prefer that block over the honest canonical chain. This is a chain-selection safety failure: an unprivileged peer with no keys can make honest nodes prefer a non-canonical chain, matching the **High** impact category — "Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

### Likelihood Explanation

The attack requires only that the Peras object-diffusion mini-protocol is active and that the attacker knows any pool ID present in the current stake distribution (public information). No keys, no stake, and no privileged access are needed. The attacker sends a batch of votes attributed to legitimate pools; each passes `validatePerasVote` because the pool ID resolves in the stake distribution. Once quorum is reached, the forged certificate is stored and applied to chain selection.

### Recommendation

`validatePerasVote` must verify the vote's cryptographic signature against the voter's public key retrieved from the stake distribution before returning `Right`. The `_params` argument (currently discarded) should supply the necessary cryptographic context. Similarly, `validatePerasCert` must verify the aggregate BLS signature over the claimed voters before accepting a certificate. Both functions should be implemented before the Peras object-diffusion protocol is enabled on any network, as the current stubs provide no protection against forged votes or certificates from any connected peer.

### Proof of Concept

1. Observe the current stake distribution to enumerate any pool ID `P` with positive stake.
2. Construct a `PerasVote` (or the abstract `Vote crypto EveryoneVotes`) with `pvVoteRound = R`, `pvBoostedBlock = B` (attacker-chosen block hash), `pvSeatIndex` matching `P`'s seat, and an arbitrary or zeroed `pvSignature`.
3. Send this vote to a target node via the Peras vote object-diffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; `lookupPerasVoteStake` finds `P` in `sd` and returns its stake; the vote is stored as `ValidatedPerasVote`.
5. Repeat with enough distinct pool IDs to exceed the quorum threshold.
6. `votesReachQuorum` returns `Just ValidatedPerasVotesWithQuorum`; `forgePerasCert` produces a `ValidatedPerasCert` boosting block `B`.
7. The node's chain selection now assigns `B` a Peras boost, potentially causing it to prefer `B` over the honest canonical tip.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-265)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```
