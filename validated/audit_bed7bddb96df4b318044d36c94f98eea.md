### Title
Stub `validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates, Bypassing Cryptographic Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation whatsoever. This stub is wired directly into the production Peras certificate diffusion inbound path (`makePerasCertPoolWriterFromChainDB`), meaning any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted, stored in the ChainDB, and used to boost chain selection.

### Finding Description

The `BlockSupportsPeras` default instance, explicitly labeled as a temporary placeholder, implements `validatePerasCert` as:

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

This function accepts every certificate unconditionally — the `params` argument is used only to extract `perasWeight`, and `cert` is never inspected for cryptographic validity, round consistency, quorum proof, or any other invariant.

This stub is the `validateCert` argument passed directly into `processCerts` in the production inbound path:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions results into valid/invalid; since `validatePerasCert` always returns `Right`, the invalid branch is never taken and every certificate is timestamped and added to the ChainDB: [3](#0-2) 

The NTN layer wires this writer directly to the Peras certificate diffusion mini-protocol, which is reachable by any connecting peer: [4](#0-3) 

The analog to the Vyper `raw_call` bug is exact: just as Vyper silently accepts a `value` parameter alongside `is_delegate_call=True` without rejecting the invalid combination, `validatePerasCert` silently accepts every certificate alongside its `params` argument without performing any of the checks those params are meant to enforce.

### Impact Explanation

Every accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is applied to chain selection to boost the certified block. An attacker who injects a fake certificate for an arbitrary block causes honest nodes to apply a Peras boost to that block, potentially making a weaker or adversarial chain appear preferred. This is a **bypass of Peras certificate verification** that enables unauthorized certificate acceptance and chain-selection manipulation.

**Impact category:** Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection distortion.

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is open to any NTN peer. No stake, keys, or privileges are required. An attacker needs only to connect and send a well-serialized `PerasCert` with an arbitrary round number and block point. The stub is the current production implementation (the degenerate instance covers all `StandardHash blk`). [5](#0-4) 

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed voter set.
2. That the claimed voters form a valid quorum (total stake ≥ threshold).
3. That the certified block and round are consistent with the current ledger view.

Until a real implementation is available, the inbound certificate path should reject all certificates rather than accept them unconditionally, to avoid the chain-selection impact.

### Proof of Concept

1. Connect to a node as an NTN peer.
2. Serialize a `PerasCert` with `pcCertRound = <target round>` and `pcCertBoostedBlock = <adversarial block point>`.
3. Send it via the Peras certificate diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight mkPerasParams}`.
5. The certificate is stored in ChainDB and the adversarial block receives a Peras chain-selection boost, causing honest nodes to prefer it over the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
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
