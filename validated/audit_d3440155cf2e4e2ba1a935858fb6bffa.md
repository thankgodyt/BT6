### Title
Peras Certificate Validation Stub Allows Any Peer to Inject Arbitrary Certificates and Manipulate Chain Selection - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

### Summary

The Peras certificate validation function `validatePerasCert` is a stub that unconditionally accepts every inbound certificate as valid. Any unprivileged peer can send a crafted `PerasCert` over the `PerasCertDiffusion` mini-protocol, have it accepted without any cryptographic or quorum check, and trigger chain selection that boosts an arbitrary block — the direct analog of the Hermez "anyone can vote with any weight at any time" timing/authorization bug.

### Finding Description

`validatePerasCert` in the universal `BlockSupportsPeras` instance always returns `Right`:

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

This stub is the function called by `processCerts` in the production inbound certificate handler:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- ← always Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` timestamps the certificate with the local wall-clock and immediately forwards it to `addPerasCertAsync`, which enqueues it for chain selection: [3](#0-2) 

`chainSelSync` then triggers `chainSelectionForBlock` for the boosted block, potentially switching the node to a fork: [4](#0-3) 

The inbound path is wired directly to the node-to-node diffusion layer: [5](#0-4) 

### Impact Explanation

Because `validatePerasCert` never rejects a certificate, an attacker can:

1. Craft a `PerasCert` claiming any `pcCertRound` and any `pcCertBoostedBlock` (a block on an adversarial fork).
2. Send it over the `PerasCertDiffusion` mini-protocol.
3. The receiving node accepts it, stores it in `PerasCertDB`, and runs chain selection for the boosted block.
4. The boosted block receives `perasWeight` (default 15) extra weight, which can make the adversarial fork heavier than the honest chain.
5. The node switches to the adversarial fork.

This is a **Critical** bypass of certificate/signature validation: an unprivileged peer can make an honest node accept an invalid certificate and prefer a non-canonical chain, violating consensus safety. The Peras weight boost is specifically designed to be large enough to overcome honest chain growth, so a single forged certificate is sufficient to cause a fork switch.

### Likelihood Explanation

The attack requires only a network connection to a Peras-enabled node and the ability to send a well-formed (but cryptographically unsigned) `PerasCert` CBOR message. No stake, keys, or special privileges are needed. The `PerasCertDiffusion` mini-protocol is open to all peers. Likelihood is **High** once Peras is activated on a live network.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate carries a valid aggregate signature from a quorum of eligible committee members for the claimed round.
- The boosted block point is a known, valid block.
- The round number is within the valid range for the current epoch.

Until real validation is in place, inbound certificates from untrusted peers should be rejected entirely, or the `PerasCertDiffusion` mini-protocol should not be enabled on production nodes.

### Proof of Concept

1. Connect to a Peras-enabled node as a peer.
2. Send a `PerasCertDiffusion` message containing a `PerasCert` with:
   - `pcCertRound = <current round>`
   - `pcCertBoostedBlock = <point of a block on an adversarial fork>`
3. Observe via tracing that `ChainSelectionForBoostedBlock` fires and the node switches to the adversarial fork.

The CBOR encoding of `PerasCert` is straightforward (2-element list: round number + block point): [6](#0-5) 

No cryptographic material is required because `validatePerasCert` ignores the certificate content entirely and returns `Right` unconditionally. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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
