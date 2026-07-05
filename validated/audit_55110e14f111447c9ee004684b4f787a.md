### Title
Peras Vote Validation Checks Stake Membership But Omits Signature Verification, Allowing Any Peer to Forge Votes and Manufacture a Quorum - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasVote` checks that a vote's `pvVoteVoterId` appears in the stake distribution, but the `PerasVote` data type carries **no signature field** and the validation function performs **no cryptographic verification**. Any unprivileged peer can craft votes impersonating any eligible voter, accumulate a manufactured quorum, and cause the node to forge and accept a Peras certificate boosting an attacker-chosen block. The companion `validatePerasCert` function is even more permissive: it unconditionally returns `Right` for every inbound certificate, accepting any crafted certificate with no checks whatsoever.

---

### Finding Description

**Root cause — missing signature field and no signature check in `validatePerasVote`:**

The catch-all `BlockSupportsPeras` instance (the only instance in the repository) defines `PerasVote` without a signature field:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- no signature field
  }
```

The validation function checks only stake-distribution membership:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

This is structurally identical to the external report's pattern: `recoverERC20` guards against `stakingToken` but not `rewardsToken`; here, `validatePerasVote` guards against an unknown voter ID but not against an unauthenticated voter identity.

**Root cause — `validatePerasCert` accepts every certificate unconditionally:**

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No round-number bounds, no quorum proof, no aggregate-signature check.

**Attacker-controlled entry path:**

Both functions are wired directly into the object-diffusion inbound path for unprivileged peers:

```haskell
-- makePerasVotePoolWriterFromChainDB (production path)
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
```

`processVotes` calls this lambda for every vote received from a remote peer, then adds passing votes to the `PerasVoteDB`. Once enough crafted votes accumulate, `votesReachQuorum` triggers `forgePerasCert` (which also performs no real validation), producing a `ValidatedPerasCert` that is stored and applied to chain selection.

---

### Impact Explanation

**Severity: High — Peras voting/certificate check bypass enabling unauthorized certificate acceptance.**

1. An unprivileged peer enumerates eligible voter IDs from the public stake distribution.
2. It sends crafted `PerasVote` messages, one per eligible voter, all targeting an attacker-chosen block `B`.
3. Each vote passes `validatePerasVote` (stake-distribution lookup succeeds; no signature is required).
4. `votesReachQuorum` fires; `forgePerasCert` produces a `ValidatedPerasCert` boosting `B`.
5. The boost is applied to chain selection, causing the honest node to prefer `B` over the canonical chain tip.

For `validatePerasCert`: a single crafted certificate message is sufficient to inject a boost for any block, bypassing the entire quorum mechanism.

---

### Likelihood Explanation

The object-diffusion mini-protocol is reachable by any peer that can establish a node-to-node connection — no keys, no stake, no privileged access required. The stake distribution is public. Constructing a valid-looking `PerasVote` requires only knowing a `PerasVoterId` (a `KeyHash`) present in the distribution, which is observable on-chain. No brute force is needed.

---

### Recommendation

1. **Add a `pvVoteSignature` field** to the `PerasVote` data type (analogous to how the `WFALS` and `EveryoneVotes` committee implementations carry a `VoteSignature` field in their `Vote` types).
2. **Verify the signature** in `validatePerasVote` using the voter's public key retrieved from the stake distribution, mirroring `implVerifyVote` in `EveryoneVotes.hs` and `WFALS.hs`.
3. **Add quorum-proof and aggregate-signature checks** to `validatePerasCert` before returning `Right`.
4. Until the full Peras committee plumbing is in place, **disable the object-diffusion inbound path** for Peras votes/certs rather than accepting them with stub validation.

---

### Proof of Concept

**Crafted vote injection (no keys needed):**

1. Connect to a target node via the object-diffusion mini-protocol.
2. Read the current `PerasVoteStakeDistr` (public, available via the ledger state query protocol).
3. For each `PerasVoterId` `vid` in the distribution, send:
   ```
   PerasVote { pvVoteRound = <current round>
             , pvVoteBlock = <attacker-chosen block point>
             , pvVoteVoterId = vid }
   ```
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; `lookupPerasVoteStake` succeeds for every `vid`; all votes are accepted.
5. `votesReachQuorum` fires once total stake exceeds the quorum threshold; `forgePerasCert` produces a `ValidatedPerasCert` boosting the attacker-chosen block.

**Crafted certificate injection (single message):**

1. Send a single `PerasCert { pcCertRound = r, pcCertBoostedBlock = <attacker block> }`.
2. `validatePerasCert` returns `Right` unconditionally.
3. The certificate is stored and its boost is applied to chain selection.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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
