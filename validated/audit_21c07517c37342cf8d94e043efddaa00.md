### Title
Unconditional Peras Certificate Acceptance Bypasses Chain-Selection Authorization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or structural checks. Because this function is the only gate between a peer-supplied `PerasCert` and the `ChainDB`, any unprivileged node-to-node peer can inject arbitrary Peras certificates that boost any block point, directly manipulating chain selection weight.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory validation step before a certificate is stored:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only concrete instance in the codebase is the catch-all `instance StandardHash blk => BlockSupportsPeras blk`, which implements this method as:

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

This is not a dead-code path. The production node-to-node handler wires `makePerasCertPoolWriterFromChainDB` directly into the `hPerasCertDiffusionClient` handler:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getCertIds chainDB)
    (validatePerasCert mkPerasParams)   -- always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [3](#0-2) 

`processCerts` partitions the validation results and adds all certs that pass — which is every cert, unconditionally:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

A `PerasCert` contains only a round number and a `Point blk` (the block to boost). No committee membership proof, no quorum signature, no VRF output — nothing is checked. The `grep_search` confirms there is no other `validatePerasCert` definition anywhere in the codebase; the unconditional instance is the only one. [5](#0-4) 

---

### Impact Explanation

A Peras certificate boosts the chain-selection weight of the block it targets. The default `perasWeight` is `PerasWeight 15`:

```haskell
perasWeight = PerasWeight 15
``` [6](#0-5) 

Chain selection compares total weight (block number + weight boost). A boost of 15 means a chain containing the boosted block is preferred over an honest chain that is up to 15 blocks longer. An attacker who injects a certificate targeting the tip of their adversarial fork causes the victim node to prefer that fork over the honest chain, constituting a **chain-selection safety failure** triggered by a crafted network message from an unprivileged peer.

This matches: *High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The `PerasCertDiffusion` protocol is fully wired into the node-to-node application stack and the validation bypass requires only that a peer send a well-formed CBOR-encoded `PerasCert` message. No stake, no keys, no prior relationship is needed. The `PerasCert` wire format is simple (round number + block point) and fully documented by the `Serialise` instance. [7](#0-6) 

---

### Recommendation

Replace the unconditional `Right` body of `validatePerasCert` with genuine validation before the `PerasCertDiffusion` protocol is enabled in any environment where adversarial peers are possible. At minimum, the implementation must verify:

1. The certificate carries a valid quorum of committee-member signatures covering the claimed `(roundNo, boostedBlock)` pair.
2. Each signing committee member was eligible for the claimed round (VRF/stake-based sortition check).
3. The boosted block point exists and is within the allowed age window (`perasCertMaxRounds`).

Until real validation is implemented, the `hPerasCertDiffusionClient` handler should be disabled or gated behind a feature flag that is off by default, so that the unconditional acceptance cannot be reached from the network.

---

### Proof of Concept

On a private testnet with two nodes A (victim) and B (attacker):

1. Node B connects to node A via the node-to-node protocol and negotiates the `PerasCertDiffusion` mini-protocol.
2. Node B crafts a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <tip of B's adversarial fork>` and sends it as a `MsgNewObjects` message.
3. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert`, receives `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`, and stores the cert via `ChainDB.addPerasCertAsync`.
4. Chain selection on node A now assigns weight `blockNo + 15` to any chain containing B's boosted block, causing A to prefer B's fork over the honest chain if the honest chain is not more than 15 blocks ahead. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-328)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
