### Title
Stub `validatePerasCert` Unconditionally Accepts Any Inbound Peras Certificate, Enabling Fake-Certificate Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that is an explicit stub: it always returns `Right` (success) regardless of certificate content, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` over the object-diffusion mini-protocol, have it accepted as "validated", and cause the receiving node to apply a `PerasWeight 15` boost to an arbitrary block — including one on an adversarial fork — directly influencing chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The universal instance `instance StandardHash blk => BlockSupportsPeras blk` in `SupportsPeras.hs` defines `validatePerasCert` as:

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

This is the **only** instance — it applies to all block types via the `StandardHash blk` constraint. No signature is verified, no quorum proof is checked, no round-number bounds are enforced. The function unconditionally wraps the raw inbound certificate in `ValidatedPerasCert` and assigns it the full `perasWeight params` boost.

**Inbound path — `makePerasCertPoolWriterFromChainDB`:**

The production inbound certificate handler for the object-diffusion mini-protocol calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound cert; because `validatePerasCert` always returns `Right`, every cert passes and is forwarded to `ChainDB.addPerasCertAsync`. [3](#0-2) 

**Chain-selection trigger — `chainSelSync`:**

Once the cert is in the `PerasCertDB`, `chainSelSync` processes it. If the cert's `pcCertBoostedBlock` is present in the `VolatileDB`, it immediately triggers `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Weight boost applied in chain comparison:**

Chain selection uses `WeightedSelectView`, which adds `wsvWeightBoost` (the sum of all Peras boosts on a fragment) to `wsvBlockNo` to compute `wsvTotalWeight`. A candidate chain is preferred if its `wsvTotalWeight` exceeds the current selection's:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier $ ...)
``` [5](#0-4) 

The default `perasWeight` is `PerasWeight 15`: [6](#0-5) 

**Exploit flow:**

1. Attacker connects as an unprivileged peer.
2. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = <adversarial block hash> }` via the object-diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. Cert is stored in `PerasCertDB` and `addPerasCertAsync` is called.
5. `chainSelSync` finds the adversarial block in `VolatileDB` and triggers chain selection for it.
6. The adversarial fork's `wsvTotalWeight` = `blockNo + 15`; if this exceeds the honest chain's `blockNo`, the node switches forks.
7. Attacker can repeat with multiple fake certs for the same block (the DB deduplicates by round number, but different round numbers are accepted), stacking boosts.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can inject an arbitrary number of fake certificates (one per round number) that each add `PerasWeight 15` to any block in the `VolatileDB`. A fork that is up to 15 blocks shorter than the honest chain per fake certificate can be made to appear heavier, causing the node to switch to a non-canonical chain. This is a **chain-selection manipulation** vulnerability: an honest node is made to prefer a less-secure or adversarially-controlled chain without any stake, key material, or operator access. This matches the **High** impact category: "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any peer that connects to a node with Peras enabled. The `PerasCert` structure requires only a round number and a block point — no cryptographic material — so crafting a valid-looking certificate is trivial. The only gate is that Peras must be enabled (non-default), but the code is production-ready and the feature flag exists for deployment.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate contains a valid aggregate signature (or equivalent quorum proof) over the `(round, block)` pair.
2. The signing committee members are eligible for the given round per the stake distribution.
3. The total signing stake meets the `perasQuorumStakeThreshold`.
4. The `pcCertRound` is within the valid range relative to the current chain tip.

Until real validation is implemented, inbound certificates from untrusted peers should be rejected entirely when Peras is enabled, or the feature should remain disabled in production deployments.

---

### Proof of Concept

On a private testnet with Peras enabled:

```
-- Attacker constructs a fake certificate pointing to a block on an adversarial fork:
let fakeCert = PerasCert
      { pcCertRound      = PerasRoundNo 42          -- any unused round number
      , pcCertBoostedBlock = BlockPoint slot adversarialHash
      }

-- Send via object-diffusion cert mini-protocol to the target node.
-- processCerts calls validatePerasCert mkPerasParams fakeCert
--   => Right (ValidatedPerasCert { vpcCert = fakeCert, vpcCertBoost = PerasWeight 15 })
-- chainSelSync triggers chainSelectionForBlock for adversarialHash.
-- WeightedSelectView: adversarialFork.totalWeight = blockNo(adversarialFork) + 15
-- If blockNo(adversarialFork) + 15 > blockNo(honestChain), node switches to adversarial fork.
```

The `PerasCert` CBOR serialisation encodes only `pcCertRound` and `pcCertBoostedBlock` — no proof field exists in the current data type — confirming that the stub is the only validation gate in the entire inbound path. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-174)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
