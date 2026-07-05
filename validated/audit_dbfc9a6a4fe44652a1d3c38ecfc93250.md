### Title
Peras Certificate and Vote Validation Stubs Accept Any Peer-Crafted Input Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass default instance — explicitly marked as a "degenerate instance for all blks to get things to compile" — implements both `validatePerasCert` and `validatePerasVote` as stubs that skip all cryptographic checks. These stubs are wired into the live inbound certificate and vote processing pipelines. An unprivileged peer can send a crafted `PerasCert` or `PerasVote` message that is accepted unconditionally, causing a certificate to be stored and used to boost an adversarially chosen block's chain weight in Peras chain selection.

---

### Finding Description

**Root cause 1 — `validatePerasCert` always returns `Right`:**

The default instance of `BlockSupportsPeras` implements `validatePerasCert` as:

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

No BLS aggregate signature is verified, no voter eligibility proofs are checked, no quorum threshold is confirmed. Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost. [1](#0-0) 

This stub is directly wired into the live inbound certificate pool writer used by both the standalone `PerasCertDB` path and the `ChainDB` path:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

**Root cause 2 — `validatePerasVote` skips BLS signature verification:**

The default instance of `validatePerasVote` only performs a stake-distribution membership lookup; it never verifies the BLS vote signature or the VRF eligibility proof:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [3](#0-2) 

`lookupPerasVoteStake` is a plain `Map.lookup` on `pvVoteVoterId`: [4](#0-3) 

Any peer that knows a valid `PerasVoterId` (a `KeyHash StakePool`, which is public on-chain data) can forge a vote attributed to that pool and have it accepted with the pool's full stake weight. This stub is wired into both the `PerasVoteDB` and `ChainDB` inbound vote pool writers: [5](#0-4) 

**Quorum and certificate forging path:**

Once enough forged votes accumulate in `updatePerasRoundVoteStates`, `votesReachQuorum` fires and `forgePerasCert` is called, producing a `ValidatedPerasCert` that is stored and used to boost the adversarially chosen block: [6](#0-5) 

The `stakeAboveThreshold` comparison itself has an acknowledged unit-mismatch TODO (absolute vs. relative `PerasVoteStake`), which further undermines the integrity of the quorum check: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can:

1. **Direct certificate injection**: Send a `PerasCert` for any block point and any round number. `validatePerasCert` accepts it unconditionally. The certificate is stored and the boosted block receives `perasWeight` additional chain weight in Peras chain selection, causing honest nodes to prefer an adversarially chosen (potentially invalid) chain.

2. **Vote-based certificate forging**: Send crafted `PerasVote` messages impersonating high-stake pool IDs (all public). Because no BLS signature is checked, votes are accepted with the impersonated pool's full stake. Once forged votes exceed the quorum threshold, a certificate is automatically forged for the attacker's chosen block target.

Both paths result in a **Peras certificate being accepted for an adversarially chosen block**, directly manipulating chain selection. This matches the allowed impact scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The attack requires only knowledge of valid `PerasVoterId` values (public `KeyHash StakePool` values, observable on-chain or from the stake distribution snapshot) and the ability to connect as a peer and send mini-protocol messages. No private keys, no stake, no operator access are needed. The vulnerable code is in the live inbound processing path, not gated behind any feature flag.

---

### Recommendation

1. Replace the degenerate `validatePerasCert` default instance with a real implementation that verifies the BLS aggregate signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed voters, confirms each voter's eligibility (persistent seat or VRF proof), and checks that the total stake of the voters exceeds the quorum threshold. The concrete types and crypto primitives for this already exist in `Ouroboros.Consensus.Peras.Cert.V1` and `Ouroboros.Consensus.Committee.WFALS`.

2. Replace the degenerate `validatePerasVote` default instance with a real implementation that verifies the BLS vote signature and, for non-persistent members, the VRF eligibility proof, as already implemented in `implVerifyVote` in `Ouroboros.Consensus.Committee.WFALS`.

3. Resolve the `stakeAboveThreshold` unit-mismatch TODO so that the quorum check operates on normalized (relative) stake values consistently.

4. Track resolution via the referenced issues (`cardano-peras/issues/73`, `cardano-peras/issues/120`).

---

### Proof of Concept

**Certificate injection path:**

1. Connect to a node as a peer via the Peras certificate mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = <adversarial block point>`.
3. Send it. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. The certificate is stored in the `PerasCertDB` / `ChainDB`. The adversarial block now carries a `perasWeight` boost in chain selection.

**Vote-based quorum forging path:**

1. Observe the public stake distribution to identify high-stake `PerasVoterId` values.
2. For a target round `R` and adversarial block point `B`, send `N` crafted `PerasVote` messages each with a distinct high-stake `pvVoteVoterId`, `pvVoteRound = R`, `pvVoteBlock = B`.
3. `validatePerasVote` accepts each vote (only `lookupPerasVoteStake` is checked; no BLS signature verification).
4. `updatePerasRoundVoteStates` accumulates stake. Once `stakeAboveThreshold` is satisfied, `forgePerasCert` is called and a certificate for block `B` is stored, boosting it in chain selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```
