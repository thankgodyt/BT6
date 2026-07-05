### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` return, performing zero cryptographic or structural validation on Peras certificates received from peers. Any unprivileged peer can send a crafted certificate that is accepted without verification, applying an unearned chain-selection boost to an arbitrary block and potentially causing honest nodes to prefer a non-canonical chain.

---

### Finding Description

The degenerate `instance StandardHash blk => BlockSupportsPeras blk` in `SupportsPeras.hs` provides the production-wired implementation of `validatePerasCert`. The body unconditionally wraps the caller-supplied certificate in `Right` and assigns it the configured `perasWeight`, with no signature check, no round-number check, no boosted-block ancestry check, and no committee-membership check:

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

This instance is the only one in the codebase — it is the universal catch-all for every `StandardHash blk`. The `validatePerasCert` method is the sole gate between a network-received `PerasCert` and a `ValidatedPerasCert` that carries a chain-selection boost weight. Because the gate is absent, the type-level distinction between `PerasCert` (untrusted) and `ValidatedPerasCert` (trusted) is meaningless at runtime.

The inbound path is wired in the node-to-node handler layer:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

The `objectDiffusionInbound` handler calls the pool writer's `opwAddObjects`, which calls `validatePerasCert` on each received certificate before storing it. Because `validatePerasCert` always succeeds, every certificate from every peer is stored and its boost is applied.

The `BlockSupportsPeras` class contract requires `validatePerasCert` to authenticate the certificate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
``` [3](#0-2) 

The `ValidatedPerasCert` carries a `vpcCertBoost` field that is consumed by chain selection to prefer the boosted block. With no validation, an attacker controls both the boosted block (`pcCertBoostedBlock`) and the round number (`pcCertRound`) in the certificate. [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any block as the boosted block for any round. The receiving node accepts it unconditionally, stores it, and applies the `perasWeight` boost to that block during chain selection. This lets the attacker steer an honest node toward a non-canonical chain by boosting an adversarial fork, or away from the canonical chain by boosting a stale or invalid tip. This is a **High**-severity chain-selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is active in the node-to-node handler and accepts inbound certificates from any connected peer. No authentication, stake check, or round-validity check is required to connect and send a certificate. The exploit requires only a TCP connection to a listening node and the ability to serialize a `PerasCert` value, which is fully described by the public `Serialise` instance. Likelihood is **High** once Peras is enabled on a live network.

---

### Recommendation

Replace the stub body of `validatePerasCert` in the `instance StandardHash blk => BlockSupportsPeras blk` with a real implementation that:

1. Verifies the certificate's aggregate BLS/committee signature against the declared voter set and the `(electionId, candidate)` pair.
2. Checks that the boosted block is a known ancestor within the allowed round window.
3. Checks that the voter set meets the quorum threshold for the given round.
4. Rejects certificates whose `pcCertRound` is outside the acceptable window relative to the current tip.

Until the real implementation is ready, the stub should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), consistent with the existing comment that the empty stake distribution causes all *votes* to be considered invalid.

---

### Proof of Concept

1. Connect to a target node's node-to-node port.
2. Perform the handshake and negotiate a version that includes `PerasCertDiffusion`.
3. Serialize and send a `PerasCert` with `pcCertBoostedBlock` pointing to the tip of an adversarial fork and `pcCertRound` set to the current Peras round.
4. The node calls `validatePerasCert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` without any check.
5. The certificate is stored via `makePerasCertPoolWriterFromChainDB` and the adversarial fork receives the full Peras boost weight in chain selection, causing the node to switch to or retain the adversarial chain. [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-385)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-409)
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
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
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
```
