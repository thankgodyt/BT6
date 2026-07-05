### Title
Peras Certificate and Vote Validation Stubs Always Accept — Bypass of Certificate/Vote Verification (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance defines `validatePerasCert` and `validatePerasVote` as stub implementations that perform no cryptographic verification. `validatePerasCert` unconditionally returns `Right` for every certificate it receives. `validatePerasVote` only checks stake-table membership but never verifies the vote's cryptographic signature. Both functions are called from the live Peras object-diffusion mini-protocol handlers. An unprivileged peer can therefore inject arbitrary forged certificates or votes that pass validation, causing them to be stored in the `PerasVoteDB` and used to manipulate Peras chain-selection weight.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` and `validatePerasVote` as the mandatory cryptographic gatekeepers for Peras objects received over the network. The class definition is correct and carries proper error types (`PerasValidationErr`). However, the **only concrete instance** that exists in the production codebase — the blanket `instance StandardHash blk => BlockSupportsPeras blk` — implements both functions as acknowledged stubs:

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

`validatePerasCert` ignores the certificate's content entirely and always returns `Right`. [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

`validatePerasVote` only checks that the voter's pool ID appears in the stake distribution; it never verifies the vote's cryptographic signature. [2](#0-1) 

These stubs are called directly from the live object-diffusion mini-protocol handlers:

- `Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` calls `validatePerasCert` before storing a received certificate. [3](#0-2) 
- `Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs` calls `validatePerasVote` before storing a received vote. [4](#0-3) 

Once a certificate is accepted by `validatePerasCert`, it is wrapped in `ValidatedPerasCert` and stored in the `PerasVoteDB`. [5](#0-4) 

Accepted certificates contribute a `vpcCertBoost` weight to the `PerasWeightSnapshot`, which is then consumed by `compareAnchoredFragments` during chain selection. [6](#0-5) 

This is the direct structural analog to the external report: the validation functions are **defined** with correct signatures and error types, but the implementations are stubs that never actually enforce the invariants they are supposed to guard — exactly as the `MarginCalculator` events were defined but never emitted.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for an arbitrary block and broadcast it via the Peras object-diffusion mini-protocol. Because `validatePerasCert` always returns `Right`, the forged certificate is accepted, stored, and its boost weight is applied during chain selection. This allows the attacker to make an honest node prefer a non-canonical or adversarially chosen chain by artificially inflating the Peras weight of a target fork. This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

Similarly, a peer can forge votes for any block from any pool ID that appears in the stake distribution (no signature check), accumulate a quorum, and trigger certificate forging for an arbitrary target block. [7](#0-6) 

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the production node codebase and is reachable by any connected peer. No special privileges, key material, or stake majority are required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` or `PerasVote` message. The stub implementations are the **only** implementations in the codebase; there is no override for Cardano block types. Likelihood is **High** once Peras is enabled on a network, and **Medium** on any testnet or private network where Peras object diffusion is active today.

---

### Recommendation

- **Short term:** Replace the stub `validatePerasCert` and `validatePerasVote` implementations with actual cryptographic verification before enabling Peras object diffusion on any network. At minimum, gate the object-diffusion handlers so they reject all objects when no real validation implementation is present.
- **Long term:** Add property-based tests that confirm `validatePerasCert` rejects certificates with invalid aggregate BLS signatures, and `validatePerasVote` rejects votes with invalid individual signatures, mirroring the recommendation in the external report to expand test coverage for key validation paths.

---

### Proof of Concept

1. Connect to a node with Peras object diffusion enabled.
2. Construct a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = p` pointing to an attacker-chosen block `p` on a minority fork.
3. Serialize it as CBOR and send it via the Peras certificate diffusion mini-protocol.
4. The node calls `validatePerasCert params cert` → returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally. [8](#0-7) 
5. The certificate is stored in `PerasVoteDB` and its boost weight is added to the `PerasWeightSnapshot`.
6. `compareAnchoredFragments` now assigns elevated weight to the fork containing block `p`, causing the node to switch to the attacker's preferred chain. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-265)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-192)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
```
