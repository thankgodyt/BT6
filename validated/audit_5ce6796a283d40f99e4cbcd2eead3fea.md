After thorough analysis of the codebase, I found a valid analog.

---

### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance unconditionally accepts every incoming Peras certificate without performing any cryptographic or quorum validation. An unprivileged peer can craft a fake `PerasCert` for any block, have it accepted by an honest node, and cause that node to apply a `perasWeight`-sized chain-weight boost to an adversarial block, potentially flipping chain selection away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` instance for `StandardHash blk` — the only instance in the codebase — provides a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives:

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

No signature verification, no committee-membership check, and no quorum check are performed. The full `perasWeight` boost (default: 15 blocks) is granted to every certificate regardless of its content.

This stub is wired directly into the production certificate-ingestion path. `processCerts` in `PerasCert.hs` calls it for every certificate received from a peer:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` is invoked from `makePerasCertPoolWriterFromChainDB`, the writer used by the live node: [3](#0-2) 

Once accepted, the certificate is stored in `PerasCertDB`. `implGetWeightSnapshot` then builds a `PerasWeightSnapshot` from every stored certificate:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds)
  ]
``` [4](#0-3) 

That snapshot is consumed by `chainSelectionForBlock` during every chain-selection event: [5](#0-4) 

`totalWeightOfFragment` adds the boost to the fragment's block-count weight, and the result drives `preferAnchoredCandidate`: [6](#0-5) 

---

### Impact Explanation

The analog to the external report is exact:

| External report | This codebase |
|---|---|
| `executePipelineConvert` applies a deltaB penalty but ignores BDV decrease | `validatePerasCert` applies no validation at all |
| User retains Grown Stalk they did not earn | Adversarial block receives `perasWeight` chain-weight boost it did not earn |
| Attacker can repeat to accumulate unbounded Stalk | Attacker can inject one certificate per round to keep a minority chain preferred |

A fake certificate for a block on an adversarial fork adds `perasWeight = 15` to that fork's total weight. If the adversarial fork is within 15 blocks of the honest tip, the honest node will switch to it. Because `takeVolatileSuffix` uses `totalWeightOfFragment` to determine the immutable prefix, the boosted block also becomes harder to roll back, compounding the effect. [7](#0-6) 

Impact class: **Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

---

### Likelihood Explanation

The attack requires only a peer connection and the ability to send a `PerasCert` message over the ObjectDiffusion mini-protocol. No stake, no keys, and no special privileges are needed. The stub is the only `BlockSupportsPeras` instance in the codebase and is unconditionally used in the live node's certificate-ingestion pipeline.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the cryptographic signatures on each vote bundled in the certificate.
2. Confirms each signer is a member of the voting committee for the given round (using the epoch's stake snapshot).
3. Confirms the aggregate stake of the signers exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.

Until this is done, the node should refuse to accept externally sourced Peras certificates entirely, rather than accepting them unconditionally.

---

### Proof of Concept

1. Connect to an honest node as an unprivileged peer via the ObjectDiffusion mini-protocol.
2. Craft `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }` for any block on a minority fork.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams`, which returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB`; `getWeightSnapshot` now includes `(adversarialBlockPoint, PerasWeight 15)`.
5. On the next `chainSelectionForBlock` call, `totalWeightOfFragment` adds 15 to the adversarial fork's weight.
6. If the adversarial fork's block count + 15 exceeds the honest fork's block count, `preferAnchoredCandidate` selects the adversarial fork.
7. Repeat each round to maintain the preference indefinitely.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
