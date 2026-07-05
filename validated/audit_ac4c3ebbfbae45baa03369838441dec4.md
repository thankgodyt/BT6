### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic, committee-membership, round-number, or boosted-block checks. Because the Peras certificate diffusion mini-protocol is wired into the live NTN handler, any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted, stored in the `ChainDB`, and used to boost chain-selection weight — bypassing all Peras certificate authorization.

---

### Finding Description

`BlockSupportsPeras` defines a `validatePerasCert` method that is supposed to authenticate inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole production instance (the "degenerate instance for all blks") implements this as:

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

Every certificate, regardless of content, is returned as `Right` with a full `vpcCertBoost` weight. No committee membership, cryptographic signature, round-number range, or boosted-block validity is checked.

The production NTN inbound handler wires this directly into the live diffusion path:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    -- TODO replace when actual plumbing is in place
    (validatePerasCert mkPerasParams)
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [3](#0-2) 

`processCerts` passes every certificate that is not already in the DB straight through to `ChainDB.addPerasCertAsync`: [4](#0-3) 

The accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the weight used by the Peras chain-selection logic to prefer the certified chain over competitors.

---

### Impact Explanation

A `ValidatedPerasCert` boosts the chain-selection weight of the block it certifies. An unprivileged peer that can inject a `PerasCert` for an arbitrary `(round, block-point)` pair will cause the receiving node to treat that block as having elevated weight. By crafting certificates for a non-canonical or adversarial chain, the attacker can make an honest node prefer a chain that would otherwise lose chain selection — a direct consensus safety failure.

This matches the **Critical** impact class: *Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance*, and *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain*.

---

### Likelihood Explanation

- The NTN Peras certificate diffusion mini-protocol is registered and active in the production node binary.
- The attacker needs only a standard NTN connection — no keys, no stake, no operator access.
- The bypass is total: the validator never inspects any field of the certificate.
- The only gate is the duplicate-round-number check (`alreadyInDb`), which is trivially bypassed by using a fresh round number.

Likelihood: **High**.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before the Peras certificate diffusion mini-protocol is active in any network that uses Peras chain-selection weight. At minimum, the validator must verify:

1. Committee membership and cryptographic signature of the certificate.
2. That the certified block point exists on a plausible chain.
3. That the round number is within an acceptable window relative to the current chain tip.

Until real validation is in place, the Peras certificate diffusion inbound handler should either be disabled or should reject all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

1. Establish a standard NTN connection to a target node.
2. Send a `PerasCert` message via the Peras certificate diffusion mini-protocol with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the tip of an adversarial fork
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is stored in the `ChainDB` via `addPerasCertAsync`.
5. The adversarial fork now carries Peras boost weight in chain selection, causing the honest node to prefer it over the canonical chain.

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
