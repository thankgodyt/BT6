### Title
Peras Vote Signature Verification Bypass: Any Peer Can Impersonate Any Registered Voter — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `validatePerasVote` implementation in the default `BlockSupportsPeras` instance performs no cryptographic signature verification. It only checks whether the claimed `pvVoteVoterId` exists in the `PerasVoteStakeDistr` map. Any unprivileged peer can craft a `PerasVote` claiming to be any registered stake pool voter, and the vote will pass validation and be accepted into the `PerasVoteDB`. This is the direct analog of the reported "anyone who is KYC'd can claim excess deposits" pattern: membership in the stake distribution (KYC equivalent) is the only gate, with no proof of ownership (private key control).

### Finding Description

The `validatePerasVote` function in the default `BlockSupportsPeras` instance reads:

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

The `PerasVote blk` data type in the same stub instance carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — there is no signature field. The sole check is `lookupPerasVoteStake`, which is a `Map.lookup` on `pvVoteVoterId`:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
```

The inbound network path in `processVotes` calls this validator for every vote received from a peer, then unconditionally stores passing votes in the `PerasVoteDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Once enough fake votes accumulate for the same `(round, block)` target, `updatePerasRoundVoteStates` forges a `ValidatedPerasCert` for that block, which is then submitted to `ChainDB` via `addPerasVoteWithAsyncCertHandling`. The certificate boosts the attacker-chosen block in chain selection.

The current production wiring in `NodeToNode.hs` passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, which causes all votes to be rejected today. However, this is an explicitly temporary placeholder with a TODO comment stating it will be replaced with real committee selection data when Peras plumbing is complete. The vulnerable `validatePerasVote` is the production code path that will be active once Peras is enabled.

### Impact Explanation

**High — Bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance.**

Once the stake distribution is wired (the stated intent), an unprivileged peer can:
1. Enumerate registered stake pool IDs from the public ledger state.
2. Craft `PerasVote` messages claiming to be those voters, voting for an attacker-chosen block.
3. Submit them via the Peras vote diffusion mini-protocol.
4. Cause the receiving node to forge a `ValidatedPerasCert` boosting the attacker's block.
5. This certificate influences chain selection, potentially causing the honest node to prefer a non-canonical chain.

This matches the allowed impact scope: "Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance."

### Likelihood Explanation

Once Peras is activated with a real stake distribution, the attack requires only:
- Network connectivity to a target node (no privileged access).
- Knowledge of registered stake pool key hashes (publicly available on-chain).
- Ability to send crafted `PerasVote` messages over the vote diffusion protocol.

The attack is trivially constructable by any peer. The only current mitigation — the empty stake distribution — is explicitly temporary and not a security control.

### Recommendation

The `validatePerasVote` implementation must verify a cryptographic signature proving the submitter controls the private key corresponding to `pvVoteVoterId`. The `PerasVote blk` data type must include a signature field (as the concrete `PerasVote` type in `Ouroboros.Consensus.Peras.Vote.V1` already does with `pvSignature :: VoteSignature PerasBLSCrypto`). Validation must call the appropriate `verifyVoteSignature` (as done in `implVerifyVote` for the `WFALS` and `EveryoneVotes` committee schemes) before accepting any peer-submitted vote.

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to a target node and opens the Peras vote diffusion mini-protocol (`hPerasVoteDiffusionClient` in `NodeToNode.hs`).
2. Peer sends a batch of `PerasVote` messages, each with `pvVoteVoterId` set to a different registered stake pool key hash (scraped from the public ledger), all voting for the same `(pvVoteRound, pvVoteBlock)` target.
3. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each. With a real stake distribution, `lookupPerasVoteStake` returns `Just stake` for each known voter ID — no signature is checked.
4. All votes pass and are stored via `addVote` in `PerasVoteDB`.
5. `updatePerasRoundVoteStates` accumulates stake; once the quorum threshold is crossed, `forgePerasCert` produces a `ValidatedPerasCert` for the attacker's chosen block.
6. `addPerasCertAsync` submits the certificate to `ChainDB`, boosting the attacker's block in chain selection.

**Root cause lines:** [1](#0-0) 

**Inbound network handler (entry point):** [2](#0-1) 

**Production wiring with temporary empty stake distribution:** [3](#0-2) 

**Stake lookup — the only check performed:** [4](#0-3) 

**Certificate forging triggered by accumulated fake votes:** [5](#0-4)

### Citations

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
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
