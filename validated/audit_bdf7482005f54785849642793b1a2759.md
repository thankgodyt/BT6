### Title
Peras Certificate and Vote Validation Stub Unconditionally Accepts All Peer-Supplied Objects, Enabling Fake-Certificate Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance ships two stub validators that are wired into the live peer-inbound processing pipeline. `validatePerasCert` returns `Right` for every certificate without performing any cryptographic check. `validatePerasVote` verifies only that the claimed voter ID exists in the stake distribution, but never verifies that the voter actually signed the vote. An unprivileged peer can therefore inject crafted Peras certificates or impersonate any registered stake pool as a voter, causing honest nodes to accept fake certificates that boost attacker-chosen blocks in chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

Every certificate received from a peer is unconditionally accepted and assigned the full `perasWeight` boost. No signature, no round-number range check, no boosted-block membership check.

**Root cause — `validatePerasVote` stub:** [2](#0-1) 

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

This is the direct analog of the external report's post-fix residual: the voter ID is verified to be a *valid* entry in the stake distribution (analogous to "verified to be a valid Velodrome gauge"), but the vote carries no cryptographic proof that the holder of the corresponding key actually produced it (analogous to "not verified to be the *correct* gauge for the position"). Any peer can claim any registered pool's identity.

**Live inbound pipeline — `processCerts`:** [3](#0-2) 

The stub `validatePerasCert mkPerasParams` is passed directly as the validator for all peer-supplied certificates. Certificates that pass (i.e., all of them) are forwarded to `ChainDB.addPerasCertAsync`.

**Live inbound pipeline — `processVotes`:** [4](#0-3) 

Votes are validated with `validatePerasVote mkPerasParams sd vote` where `sd` is the public stake distribution. Because no signature is checked, an attacker who knows any registered pool's `KeyHash` (public information) can fabricate votes for that pool.

**Quorum forging path:** [5](#0-4) 

`votesReachQuorum` aggregates stake from `ValidatedPerasVote` objects. Once the threshold is crossed, `forgePerasCert` produces a `ValidatedPerasCert` that is added to the ChainDB and influences chain selection.

---

### Impact Explanation

Peras certificates provide a configurable stake-weighted boost (`perasWeight`) to the block they reference during chain selection. An attacker who can inject accepted certificates for a block of their choice can make honest nodes prefer that block over the honest canonical chain, constituting a chain-selection safety failure. The attack requires no stake, no keys, and no privileged access — only the ability to send messages over the peer-to-peer diffusion layer.

This matches: **High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

The degenerate `BlockSupportsPeras` instance is the only instance in the repository (`instance StandardHash blk => BlockSupportsPeras blk`). No concrete override for `CardanoBlock` or any Shelley-era block type was found. The inbound processing functions `makePerasCertPoolWriterFromChainDB` and `makePerasVotePoolWriterFromChainDB` are production code in `ouroboros-consensus-diffusion`. Peras is under active development (several TODO markers reference open issues), so the attack surface is live in the codebase but may not yet be reachable on mainnet depending on whether the diffusion layer activates the object-pool mini-protocol. Likelihood is **Medium** given the in-progress deployment status, but the code path is unconditionally reachable once the protocol is enabled.

---

### Recommendation

1. **`validatePerasCert`**: Implement full cryptographic verification — aggregate BLS signature check over `(pcRoundNo, pcBoostedBlock)`, committee membership proof for each voter in `pcVoters`, and round-number range validation against the current chain state.
2. **`validatePerasVote`**: Add a cryptographic signature field to `PerasVote` and verify it against the voter's registered public key before accepting the vote. Membership in the stake distribution is a necessary but not sufficient condition.
3. Remove or gate the degenerate `BlockSupportsPeras` instance behind a compile-time flag so it cannot be silently used in production block types.

---

### Proof of Concept

1. Attacker connects to an honest node as a peer via the Peras object-diffusion mini-protocol.
2. Attacker reads the public stake distribution to obtain any registered pool's `PerasVoterId` (a `KeyHash`).
3. Attacker constructs `PerasVote { pvVoteRound = r, pvVoteBlock = attackerBlock, pvVoteVoterId = victimPoolId }` for enough pool IDs to exceed the quorum threshold.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; each vote passes because `lookupPerasVoteStake` finds the pool ID in `sd`.
5. `votesReachQuorum` sees total stake above threshold and calls `forgePerasCert`, producing a `ValidatedPerasCert` for `attackerBlock`.
6. Alternatively, attacker directly sends a `PerasCert` object; `processCerts` calls `validatePerasCert mkPerasParams cert` which returns `Right` unconditionally.
7. The certificate is added to ChainDB via `addPerasCertAsync`; chain selection now applies `perasWeight` boost to `attackerBlock`, potentially causing the honest node to prefer the attacker's chain over the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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
