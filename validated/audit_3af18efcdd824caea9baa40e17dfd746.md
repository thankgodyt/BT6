### Title
Peras Certificate Validation Bypass via Unconditionally-Succeeding `validatePerasCert` Stub Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` default instance implements `validatePerasCert` as an unconditional `Right`, making the validation gate in `processCerts` a no-op for every inbound certificate. An unprivileged peer connected via the object-diffusion mini-protocol can send a crafted `PerasCert` boosting any block in the VolatileDB; the certificate passes "validation", is stored in `PerasCertDB`, and triggers chain selection with a Peras weight boost applied to the attacker-chosen block, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**The intended check — `processCerts`**

`processCerts` in `PerasCert.hs` is the inbound validation gate for peer-supplied certificates:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _)            -> throw (PerasCertValidationError errs)
```

The `validateCert` argument is supplied as `validatePerasCert mkPerasParams` in both production writers: [1](#0-0) [2](#0-1) 

**The missing check — `validatePerasCert` always returns `Right`**

The default `BlockSupportsPeras` instance, which applies to **all** block types via `instance StandardHash blk => BlockSupportsPeras blk`, implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [3](#0-2) 

Every certificate unconditionally becomes a `ValidatedPerasCert`. The `partitionEithers` call in `processCerts` will always produce an empty error list, so the rejection branch (`throw (PerasCertValidationError errs)`) is unreachable. The validation gate is structurally present but functionally absent — an exact analog to the external report's missing modifier.

**The downstream effect — chain selection triggered for attacker-chosen block**

After passing the no-op validation, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message: [4](#0-3) 

In `chainSelSync`, the certificate is stored in `PerasCertDB` and chain selection is immediately triggered for the boosted block: [5](#0-4) 

The Peras weight boost (`vpcCertBoost = perasWeight params`) is applied to the attacker-chosen block, making it appear heavier than it actually is in the `PerasWeightSnapshot` used by chain comparison: [6](#0-5) 

---

### Impact Explanation

**Impact: High** — Chain selection manipulation.

An unprivileged peer can craft a `PerasCert` pointing to any block hash present in the target node's VolatileDB. Because `validatePerasCert` never rejects, the certificate is stored and the Peras weight boost is applied to the attacker-chosen block. If that block is on a fork, the boosted weight can cause the node to prefer the fork over the canonical chain, constituting a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

**Likelihood: High.**

- No special privileges, keys, or stake are required.
- Any peer connected via the object-diffusion mini-protocol can send arbitrary `PerasCert` objects.
- The default instance applies to all block types with no override; there is no production code path that performs real certificate validation.
- The attacker only needs to know a block hash present in the target's VolatileDB (obtainable via normal chain-sync).

---

### Recommendation

Implement actual cryptographic and structural validation inside `validatePerasCert` before the Peras object-diffusion mini-protocol is enabled in production. At minimum:

1. Verify the certificate's aggregate signature against the claimed committee members and election ID.
2. Verify that each claimed voter is a legitimate committee member for the given round (stake eligibility, VRF proof for non-persistent members).
3. Verify that the boosted block's slot falls within the valid Peras round window.
4. Reject certificates whose `pcCertRound` is outside the current cooldown/active window.

Until real validation is in place, the object-diffusion server for Peras certificates should not be exposed to untrusted peers.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the object-diffusion mini-protocol.
2. Obtain a block hash `H` from the target's VolatileDB (e.g., via ChainSync) that is on a fork the attacker wishes to promote.
3. Construct a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }` for any round `R` not yet in the target's `PerasCertDB`.
4. Send the certificate to the target node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally. [7](#0-6) 
6. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`; `chainSelSync` stores the certificate and calls `chainSelectionForBlock` for block `H` with the Peras weight boost applied. [8](#0-7) 
7. The node's chain comparison now treats the fork containing `H` as heavier by `perasWeight mkPerasParams`, potentially switching to the non-canonical fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L132-132)
```haskell
          (void . ChainDB.addPerasCertAsync chainDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L494-531)
```haskell
    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```
