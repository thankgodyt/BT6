### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate, Bypassing Authorization - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` typeclass implementation of `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or eligibility checks. This stub is wired directly into the production node-to-node Peras certificate diffusion inbound handler. Any unprivileged peer can therefore send an arbitrary crafted `PerasCert` that the receiving node will accept as fully valid, add to its `ChainDB`, and use to boost a target block's weight in chain selection — without any committee membership, signature, or round-number verification.

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` with a default implementation that always succeeds:

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

No committee membership check, no aggregate BLS signature verification, no round-number or target-block plausibility check is performed. Every `PerasCert` is returned as a `ValidatedPerasCert` carrying the full configured `perasWeight` boost.

**Production wiring — cert diffusion inbound handler:**

In `mkHandlers`, the Peras certificate diffusion client is wired as:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
```

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert` (the always-`Right` stub) on every inbound certificate before adding it to the `ChainDB` via `addPerasCertAsync`. There is no separate gate or real validation layer between the network and the `ChainDB` insertion.

**Contrast with vote diffusion:**

The vote diffusion inbound handler is wired with `(pure (PerasVoteStakeDistr mempty))`, which causes all inbound votes to fail validation (empty stake distribution → `lookupPerasVoteStake` always returns `Nothing` → `Left PerasValidationErr`). Votes are therefore rejected. Certificates have no equivalent guard — the stub accepts everything.

**Exploit path:**

1. Attacker connects to a target node as a normal peer (no privileged access required).
2. Attacker sends a crafted `PerasCert` for round R targeting block B (any block the attacker wants to boost, observable from the public chain).
3. `processVotes`-equivalent in the cert pool writer calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. The cert is added to the `ChainDB` via `addPerasCertAsync`, which triggers `addPerasCertAsync` → chain selection re-evaluation with the boosted weight.
5. Chain selection now treats block B as having additional Peras weight, potentially causing the node to switch to a fork containing B over the honest chain.

### Impact Explanation

This is a **bypass of Peras certificate verification**: an unprivileged peer can inject arbitrary certificates that are accepted as valid and used to influence chain selection weight. The Peras weight boost is designed to make certified blocks strongly preferred; an attacker who can inject fake certificates for any block can steer an honest node's chain selection toward a non-canonical fork. This falls under: *Bypass of certificate/vote verification checks that enables unauthorized certificate acceptance* and *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain*.

### Likelihood Explanation

Any peer reachable over the node-to-node network can trigger this. No keys, stake, or privileged access are required — only the ability to open a connection and send a well-formed `PerasCert` CBOR message. The Peras cert diffusion mini-protocol is wired into `mkHandlers` and runs for every connected peer that negotiates the relevant `NodeToNodeVersion`. The attacker needs only to know the hash of a target block (publicly observable) and the current Peras round number.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members.
2. That the claimed voters are eligible members of the committee for round R (using the ledger's stake distribution and committee selection logic, analogous to how `validatePerasVote` uses `lookupPerasVoteStake`).
3. That the round number and target block are plausible given the node's current chain state.

Until a real implementation is available, the inbound cert diffusion handler should reject all inbound certificates (analogous to how the vote handler uses `PerasVoteStakeDistr mempty` to reject all votes), rather than accepting them unconditionally.

### Proof of Concept

1. Connect to a target node as a peer negotiating the Peras cert diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <hash of a block on a minority fork>`.
3. Send it via the `PerasCertDiffusion` protocol.
4. Observe: the node calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The cert is inserted into the `ChainDB`; `getPerasWeightSnapshot` now returns a snapshot that boosts the target block.
6. Chain selection re-runs with the boosted weight; if the boosted fork is otherwise competitive, the node switches to it.

**Key code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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
