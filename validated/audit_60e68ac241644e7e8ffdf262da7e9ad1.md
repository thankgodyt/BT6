### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate Without Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance wired into the production node-to-node diffusion layer implements `validatePerasCert` as an unconditional `Right`, accepting every inbound `PerasCert` from any peer as fully valid without performing any cryptographic, committee, or quorum check. An unprivileged peer can send a crafted certificate claiming to certify an arbitrary block at an arbitrary round; the node stores it as a `ValidatedPerasCert` and applies its chain-weight boost during chain selection.

---

### Finding Description

The `BlockSupportsPeras` instance declared at `SupportsPeras.hs:318-389` is explicitly labelled a "degenerate instance for all blks to get things to compile" (issue #73). Its `validatePerasCert` implementation is:

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

This stub is the live implementation used by the production node-to-node handler. In `NodeToNode.hs`, the `hPerasCertDiffusionClient` handler is wired directly to `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on every inbound cert:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

The `makePerasCertPoolWriterFromChainDB` function in `PerasCert.hs` calls `validatePerasCert` on each received cert before storing it via `ChainDB.addPerasVoteWithAsyncCertHandling` (or the cert equivalent). Because `validatePerasCert` always returns `Right`, no signature, committee membership, quorum threshold, or round-number check is ever performed. [3](#0-2) 

The resulting `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the Peras chain-weight boost applied to the certified block during chain selection. [4](#0-3) 

---

### Impact Explanation

A `ValidatedPerasCert` stored in the ChainDB causes the consensus layer to apply a `PerasWeight` boost to the block identified by `pcCertBoostedBlock`. An attacker who injects a cert pointing to a block on a minority or adversary-controlled fork causes the victim node to prefer that fork over the honest canonical chain. This is a **High** chain-selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of the Peras protocol, without holding any stake or keys.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is an active node-to-node handler registered in `mkHandlers` and exposed to every connected peer. Any peer that speaks the protocol can send a crafted `PerasCert` CBOR message. No stake, key material, or privileged access is required. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase and is used unconditionally. [5](#0-4) 

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members.
2. That the claimed committee members were eligible for the stated round (VRF/committee selection check).
3. That the aggregate stake of the signers exceeds the quorum threshold (`perasQuorumStakeThreshold`).
4. That `pcCertRound` and `pcCertBoostedBlock` are consistent with the current ledger view.

Until a real implementation is available, the `hPerasCertDiffusionClient` handler should not be registered in the production `mkHandlers`, or should drop all inbound certs unconditionally rather than accepting them. [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a victim node as a normal peer (no keys required).
2. Attacker sends a `PerasCertDiffusion` protocol message containing a crafted `PerasCert`:
   ```
   PerasCert { pcCertRound = <target round>, pcCertBoostedBlock = <attacker fork tip> }
   ```
3. The node's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on the cert.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = perasWeight params }` unconditionally. [7](#0-6) 
5. The `ValidatedPerasCert` is stored in the ChainDB.
6. Chain selection applies `vpcCertBoost` to the attacker's chosen block, causing the node to prefer the attacker's fork over the honest canonical chain.

**Necessary vulnerable step:** `validatePerasCert` is the sole gate between a peer-supplied `PerasCert` and a `ValidatedPerasCert` stored in the ChainDB. Because it is unconditionally `Right`, the gate does not exist.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-211)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
```

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L274-290)
```haskell
mkHandlers ::
  forall m blk addrNTN addrNTC.
  ( IOLike m
  , MonadTime m
  , MonadTimer m
  , LedgerSupportsMempool blk
  , HasTxId (GenTx blk)
  , LedgerSupportsProtocol blk
  , Ord addrNTN
  , Hashable addrNTN
  ) =>
  NodeKernelArgs m addrNTN addrNTC blk ->
  NodeKernel m addrNTN addrNTC blk ->
  TxSubmissionLogicVersion ->
  Handlers m addrNTN blk
mkHandlers
  NodeKernelArgs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-12)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
-- certificates from the 'PerasCertDB' (or the 'ChainDB' which is wrapping the
-- 'PerasCertDB').
module Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert
  ( makePerasCertPoolReaderFromCertDB
  , makePerasCertPoolWriterFromCertDB
  , makePerasCertPoolReaderFromChainDB
  , makePerasCertPoolWriterFromChainDB
  ) where
```
