### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates Without Any Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function performs **zero validation** and unconditionally returns `Right` (success) for any certificate received from any peer. This is a direct structural analog to the reported vulnerability class: a function that accepts any input without checking its validity. An unprivileged peer can inject a crafted `PerasCert` for an arbitrary block point, which will be accepted as a `ValidatedPerasCert` carrying a full Peras weight boost, directly influencing chain selection.

---

### Finding Description

In `Block/SupportsPeras.hs`, the default `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) provides stub implementations for all validation functions. `validatePerasCert` at lines 353–358 performs no validation whatsoever:

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

The function is supposed to verify that a Peras certificate is cryptographically sound (e.g., that it is backed by a quorum of valid votes with valid signatures) and structurally correct (e.g., that the certified block point exists on a valid chain, that the round number is consistent). Instead, it wraps **any** input in a `ValidatedPerasCert` and returns it as valid, assigning it the full configured weight boost. [1](#0-0) 

Similarly, `validatePerasVote` at lines 363–371 only checks whether the voter's key appears in the stake distribution but performs no cryptographic signature verification on the vote body itself: [2](#0-1) 

The certificate diffusion path is live. `addPerasCertAsync` in `ChainSel.hs` accepts certificates from peers and routes them into the `CertDB`. The vote pool writer `makePerasVotePoolWriterFromChainDB` in `ObjectPool/PerasVote.hs` is wired into the node kernel and calls `validatePerasVote` on every inbound vote from a peer: [3](#0-2) 

The `ValidatedPerasCert` produced by the stub carries `vpcCertBoost = perasWeight params`, which is consumed directly by the chain selection weight snapshot logic. The `getPerasWeightSnapshot` function and the chain selection comparator use this boost to prefer certified chains: [4](#0-3) 

---

### Impact Explanation

Peras certificates carry a weight boost that causes chain selection to prefer a certified chain over an uncertified one of equal or slightly lesser length. Because `validatePerasCert` unconditionally accepts any certificate, an unprivileged peer can:

1. Craft a `PerasCert` pointing to any block on an adversarial fork.
2. Inject it via the Peras certificate diffusion mini-protocol.
3. The receiving node calls `validatePerasCert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` without any check.
4. The certificate is stored in `CertDB` and its boost is applied during chain selection.
5. The adversarial chain now appears heavier than the honest chain, causing the node to switch to it.

This is a **bypass of Peras certificate validation enabling unauthorized certificate acceptance**, which falls squarely within the allowed impact scope: *"Critical. Bypass of… certificate… checks… that enables unauthorized… certificate acceptance."* [5](#0-4) 

---

### Likelihood Explanation

The Peras vote and certificate diffusion infrastructure is present and wired into the production node kernel. The `addPerasCertAsync` entry point accepts peer-supplied certificates with no precondition on their validity beyond what `validatePerasCert` checks — which is nothing. Any node operator running a private testnet with Peras enabled, or any future mainnet deployment, is immediately exploitable by any connected peer. The attacker needs only a network connection to the node; no keys, stake, or privileged access are required.

---

### Recommendation

Before Peras is activated on any network, `validatePerasCert` must be replaced with a real implementation that:

- Verifies the cryptographic signature(s) on the certificate against the claimed committee members.
- Confirms the certified block point exists on a chain the node considers valid.
- Checks the round number is consistent with the current Peras protocol state.
- Verifies the certificate was produced by a quorum of eligible committee members for that round.

The same applies to `validatePerasVote`: the vote body's cryptographic signature must be verified, not just the voter's presence in the stake distribution.

---

### Proof of Concept

1. Connect to a node with Peras infrastructure active.
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point on adversarial fork>`.
3. Submit it via the Peras certificate diffusion protocol to `addPerasCertAsync`.
4. The node calls `validatePerasCert params cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally — no signature check, no block existence check, no round consistency check.
5. The certificate is stored in `CertDB`. On the next chain selection run, `getPerasWeightSnapshot` includes the boost for the adversarial block.
6. The adversarial chain is now preferred over the honest chain by the weight of `perasWeight params`, causing the node to adopt the adversarial fork. [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```
