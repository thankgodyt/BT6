### Title
Stub `validatePerasCert` Unconditionally Accepts All Peras Certificates, Bypassing Cryptographic Verification — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` provides stub implementations of `validatePerasCert` and `validatePerasVote` that skip all cryptographic verification. `validatePerasCert` unconditionally returns `Right` (accepts every certificate), and `validatePerasVote` only checks stake-distribution membership without verifying vote signatures or committee eligibility. Any unprivileged peer can inject crafted Peras certificates or votes that pass "validation" and are stored in `PerasCertDB`/`PerasVoteDB`, directly influencing chain selection.

---

### Finding Description

**Vulnerability class (analog to M-7):** In M-7, a liquidation order bypasses the referrer-restriction check, allowing a malicious actor to assign persistent state for another user that the legitimate user cannot override. The analog here is that the certificate/vote submission path from any peer bypasses all cryptographic authorization checks, allowing a malicious peer to inject persistent consensus state (accepted certificates) that influences chain selection.

**Root cause — `validatePerasCert` stub:**

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

This is the **only** instance of `BlockSupportsPeras` in the codebase — it is a universal instance (`instance StandardHash blk => BlockSupportsPeras blk`). Every block type uses it. The function accepts every certificate unconditionally and wraps it in `ValidatedPerasCert` with a full boost weight.

**Root cause — `validatePerasVote` stub:**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

This checks only that the voter ID appears in the stake distribution. It does **not** verify the vote signature, VRF proof of eligibility, or committee membership. Any peer that knows a valid `PerasVoterId` (which is public) can forge votes for arbitrary blocks.

**Production entry path for votes:**

`processVotes` in `ObjectPool/PerasVote.hs` is the inbound handler for peer-submitted votes. It calls the `validateVote` callback, which is wired to `validatePerasVote mkPerasParams sd vote` in both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`. Validated votes are stored in `PerasVoteDB` and aggregated; when quorum is reached, a `ValidatedPerasCert` is forged and stored in `PerasCertDB`.

**Chain selection impact:**

Per the wiki and `PerasCertDB` documentation, certificates stored in `PerasCertDB` are used by the chain selection logic to weight chains. A certificate boosts a block's chain weight by `perasWeight params`. A malicious peer can therefore cause an honest node to prefer a non-canonical chain by injecting a fake certificate for a weaker fork.

**Secondary unimplemented function — `getVotingCommitteeForElection`:**

```haskell
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```

This function in `AcrossEpochs.hs` is the intended lookup path for validating votes from previous epochs. It is unimplemented. Any code path that reaches it will crash the node at runtime. This is the direct structural analog to M-7's "state cannot be properly looked up for the correct context ID," but its impact is a node crash rather than a chain-selection manipulation.

---

### Impact Explanation

**Primary (`validatePerasCert` / `validatePerasVote`):** An unprivileged peer can submit a crafted `PerasCert` for any block. The certificate passes validation unconditionally, is stored in `PerasCertDB`, and is used by chain selection to boost that block's chain. This lets a malicious peer make an honest node prefer a non-canonical or adversarially chosen chain, violating Peras's fast-finality guarantee and potentially causing a chain-selection divergence from the honest majority.

Severity: **High** — matches "Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

**Secondary (`getVotingCommitteeForElection`):** Any peer that triggers the cross-epoch vote validation path causes a runtime `error` crash, taking the node offline. Severity: disqualified as DoS per the scope rules.

---

### Likelihood Explanation

The `processVotes` inbound handler is wired directly to the network layer via the `ObjectDiffusion` mini-protocol. Any connected peer can submit a batch of `PerasVote` or `PerasCert` objects. No privileged access, leaked keys, or stake majority is required. The attacker only needs to know a valid `PerasVoterId` (public information from the stake distribution) to forge votes, or simply send any `PerasCert` struct to inject a certificate.

---

### Recommendation

1. **Remove or gate the universal stub instance.** The `instance StandardHash blk => BlockSupportsPeras blk` stub should not be reachable in any production code path. Replace it with a type-class constraint that forces concrete block types to provide real implementations, or add a compile-time guard that prevents the stub from being used outside of test contexts.

2. **Implement `validatePerasCert`** to verify the aggregate BLS signature against the committee's public keys using `implVerifyCert` from `WFALS.hs` or `EveryoneVotes.hs`, and check that the certificate's `ElectionId` matches the expected round.

3. **Implement `validatePerasVote`** to verify the vote signature (`verifyVoteSignature`) and, for non-persistent members, the VRF eligibility proof (`evalVRF`), as already implemented in `implVerifyVote` in `WFALS.hs`.

4. **Implement `getVotingCommitteeForElection`** in `AcrossEpochs.hs` to correctly dispatch to `currEpochVotingCommittee` or `prevEpochVotingCommittee` based on the `ElectionId`'s epoch, before any cross-epoch vote validation is reachable from the network.

---

### Proof of Concept

1. Connect to a node running this codebase as an unprivileged peer via the `ObjectDiffusion` mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point on a weaker fork>`.
3. Submit the certificate. `validatePerasCert` returns `Right ValidatedPerasCert{...}` unconditionally.
4. The certificate is stored in `PerasCertDB` with full `perasWeight` boost.
5. Chain selection now weights the weaker fork higher than the honest chain, causing the node to switch to the adversarially chosen fork.

**Code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L68-74)
```haskell
-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```
