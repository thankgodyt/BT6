### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Chain-Boost Certificates — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero signature or committee-eligibility checks. Because the `PerasCertDiffusion` miniprotocol handler wires this function directly into the inbound certificate pool writer, any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block in chain selection without holding any committee credentials.

### Finding Description

**Root cause — `validatePerasCert` always succeeds:**

The catch-all `BlockSupportsPeras` instance (the only instance present in the repository) implements certificate validation as a stub that unconditionally accepts every certificate:

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
``` [1](#0-0) 

No signature over the certificate body is verified, no committee-membership proof is checked, and no eligibility witness is required. The function signature accepts a `PerasCert blk` value that is entirely attacker-controlled.

**Attacker-reachable entry path — `hPerasCertDiffusionClient`:**

The NodeToNode handler wires `makePerasCertPoolWriterFromChainDB` directly as the inbound writer for the `PerasCertDiffusion` miniprotocol:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert` (via the `validateVote`-equivalent callback) on every certificate received from a peer, then stores the result in the ChainDB if validation returns `Right`. [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate sent by any peer is stored in the ChainDB and its `vpcCertBoost = perasWeight params` weight is applied to the boosted block during chain selection.

**Contrast with the analogous vote path:**

The vote path passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, which causes `validatePerasVote` to return `Left` for every vote (voter not found in empty map), so votes are rejected. Certificates have no equivalent guard — `validatePerasCert` ignores the stake distribution entirely and always succeeds. [4](#0-3) [5](#0-4) 

### Impact Explanation

**Severity: High — chain-selection manipulation by an unprivileged peer.**

A `ValidatedPerasCert` carries a `vpcCertBoost` weight that is added to the boosted block's chain-selection score. An attacker who connects as a normal peer can craft a `PerasCert` pointing `pcCertBoostedBlock` at any block on a competing fork and send it via the `PerasCertDiffusion` miniprotocol. The receiving honest node stores the certificate and applies the boost, potentially causing it to prefer the attacker's fork over the canonical chain — a chain-selection divergence triggered by a single unauthenticated network message.

This matches the allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**High.** The `PerasCertDiffusion` miniprotocol is open to every node-to-node peer. No stake, no key material, and no prior relationship is required. The attacker only needs to establish a standard peer connection and send a single crafted `PerasCert` message. The degenerate instance is the only `BlockSupportsPeras` instance in the repository and is used for all block types.

### Recommendation

1. `validatePerasCert` must verify a cryptographic signature over the certificate body using the committee's aggregate verification key, and must confirm that the signers collectively hold sufficient stake to form a quorum — mirroring the checks already present in `implVerifyCert` for the `WFALS` and `EveryoneVotes` committee implementations.
2. Until real validation is implemented, the `hPerasCertDiffusionClient` handler should not be wired to a live ChainDB writer; it should either be disabled or connected to a no-op writer that discards all inbound certificates.
3. The degenerate catch-all instance should not silently succeed on security-critical operations; it should return `Left` (reject) by default, forcing each concrete block type to opt in to certificate acceptance explicitly.

### Proof of Concept

```
1. Attacker establishes a standard node-to-node peer connection to an honest node.
2. Attacker sends a PerasCertDiffusion message containing a crafted PerasCert:
     PerasCert { pcCertRound = <current round>
               , pcCertBoostedBlock = <point on attacker's preferred fork> }
3. The honest node's hPerasCertDiffusionClient handler receives the message and
   calls makePerasCertPoolWriterFromChainDB → processVotes-equivalent →
   validatePerasCert.
4. validatePerasCert returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })
   unconditionally — no signature checked, no committee membership verified.
5. The certificate is stored in the ChainDB.
6. Chain selection applies vpcCertBoost to pcCertBoostedBlock, potentially
   causing the honest node to switch to the attacker's fork.
``` [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-410)
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
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-152)
```haskell
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
