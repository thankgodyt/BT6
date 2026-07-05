### Title
`validatePerasCert` Accepts All Peras Certificates Without Cryptographic Verification, Enabling Unauthorized Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, accepting every inbound `PerasCert` without any cryptographic check. The `PerasCert` data type carries no signature field at all. Any unprivileged peer can craft and send a certificate for an arbitrary block via the live `perasCertDiffusionProtocol` miniprotocol; the receiving node will treat it as valid, boost that block's chain-selection weight, and potentially execute a fork switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

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

Every `PerasCert`, regardless of origin or content, is wrapped in `Right ValidatedPerasCert` and assigned the full Peras weight boost. No quorum check, no aggregate-signature check, no committee-membership check is performed.

**Root cause — `PerasCert` carries no signature field:**

```haskell
data PerasCert blk = PerasCert
  { pcCertRound        :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

There is no cryptographic material in the wire type, so even a future implementation of `validatePerasCert` would have nothing to verify unless the type is extended.

**Entry path — `hPerasCertDiffusionClient` in `NodeToNode.hs`:**

The handler is wired unconditionally into the node-to-node protocol bundle and passes every inbound certificate directly to `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` before forwarding to `addPerasCertAsync`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

Unlike the vote path — which is currently neutralised by a hardcoded empty stake distribution — the cert path has **no analogous guard**.

**Effect — `addPerasCertAsync` triggers chain selection:**

```haskell
, addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [4](#0-3) 

A forged certificate that names a non-canonical block will boost that block's Peras weight. If the boosted weight exceeds the honest chain's weight, the node executes a fork switch.

**Contrast with the vote path (currently blocked):**

The vote diffusion handler is explicitly neutralised with a hardcoded empty stake distribution, so all votes fail `validatePerasVote` today:

```haskell
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

No equivalent guard exists for the certificate path.

---

### Impact Explanation

An unprivileged peer with a standard node-to-node connection can send a `PerasCert{pcCertRound = r, pcCertBoostedBlock = p}` for any block point `p` it chooses. The receiving node will:

1. Accept it via the no-op `validatePerasCert`.
2. Store it as a `ValidatedPerasCert` carrying the full `perasWeight` boost.
3. Trigger `addPerasCertAsync`, which re-evaluates chain selection.
4. If the boosted fork is now heavier, execute a fork switch away from the honest chain.

This is a **bypass of Peras certificate/signature validation** that enables unauthorized certificate acceptance and chain-selection manipulation by any unprivileged peer — matching the "Critical" tier of the allowed impact scope.

---

### Likelihood Explanation

The `perasCertDiffusionProtocol` is included unconditionally in the `initiatorAndResponder` bundle and requires no special role or key material to participate in. Any node that can establish a standard node-to-node connection can send crafted certificates. No stake, no KES key, no VRF key, and no operator access is required.

---

### Recommendation

1. **Extend `PerasCert`** to carry an aggregate BLS signature (or equivalent) over `(pcCertRound, pcCertBoostedBlock)` produced by a quorum of eligible committee members.
2. **Implement real validation in `validatePerasCert`**: verify the aggregate signature against the committee's aggregate verification key derived from the current stake distribution, and confirm the signing set exceeds the quorum threshold.
3. **Mirror the vote-path guard** by refusing to process certificates when the committee selection context is not yet available (analogous to the empty-stake-distribution guard on the vote path).
4. **Resolve the tracked TODO** at `https://github.com/tweag/cardano-peras/issues/120` before enabling the cert diffusion protocol on any network where Peras weight influences chain selection.

---

### Proof of Concept

```
Attacker (any peer with a node-to-node connection):

1. Establish a standard NtN connection to an honest node.

2. Via perasCertDiffus

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L400-406)
```haskell
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
