### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every inbound certificate, performing no cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` boosting an arbitrary block on a fork, causing the receiving node to add a spurious Peras weight boost and switch to a non-canonical chain.

---

### Finding Description

The file `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` defines the only `BlockSupportsPeras` instance in the codebase — a universal instance for all `StandardHash blk` — with the following stub implementation of `validatePerasCert`:

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

This function accepts every certificate unconditionally and assigns it the full `perasWeight` boost (default: `PerasWeight 15`). No committee membership check, no aggregate signature verification, and no round-number plausibility check is performed.

This stub is wired directly into the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` — explicitly documented as the function for "actual production use" — passes `(validatePerasCert mkPerasParams)` as the validator to `processCerts`:

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
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, if all pass (which they always do), forwards them to `addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection then uses `preferAnchoredCandidate`, which computes `wsvTotalWeight = blockNo + weightBoost` and switches to any candidate whose total weight exceeds the current chain's: [5](#0-4) 

The weight boost stored in `PerasWeightSnapshot` is derived directly from `vpcCertBoost` of the accepted `ValidatedPerasCert`, which is always `perasWeight params = PerasWeight 15`: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` with:
- `pcCertRound`: any round number not yet in the DB
- `pcCertBoostedBlock`: the `Point` of any block on an adversarial fork present in the node's VolatileDB

The certificate passes validation unconditionally, is stored, and triggers `chainSelectionForBlock` for the boosted block. Because `wsvTotalWeight` adds `PerasWeight 15` to the fork's block number, a fork that is up to 15 blocks shorter than the honest chain will now appear heavier and be adopted. This constitutes a chain-selection manipulation: an honest node is made to prefer a non-canonical, less-secure chain without any stake majority or key compromise.

This matches the **High** impact class: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The attack requires only that the adversary:
1. Be a connected peer (no privileged access needed).
2. Know the hash of a block on a fork in the target node's VolatileDB (obtainable via normal ChainSync).
3. Send a single crafted `PerasCert` message via the Peras object-diffusion mini-protocol.

No key material, stake, or admin access is required. The entry point is a standard peer-to-peer message handler reachable from any connected node.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate committee signature over `(electionId, candidate)` using the public keys of the claimed committee members.
2. Checks that the claimed voters collectively hold at least the quorum stake threshold.
3. Verifies that the certificate's round number is consistent with the current epoch's committee selection.

Until real cryptographic validation is implemented, the `validatePerasCert` call in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` must not be deployed in any network-connected context, as it accepts all inbound certificates unconditionally.

---

### Proof of Concept

The following describes a private-testnet reproduction sequence:

1. Run two nodes, A (honest) and B (attacker), connected via the Peras object-diffusion mini-protocol.
2. Let both nodes sync to a common tip at block height H.
3. Attacker node B withholds a fork block F at height H (same height as honest tip, different hash), keeping it in its VolatileDB but not diffusing it.
4. B sends node A the fork block F via BlockFetch so it lands in A's VolatileDB (but is not yet selected, since it ties with the honest tip).
5. B crafts a `PerasCert` with `pcCertRound = 1` and `pcCertBoostedBlock = blockPoint F`, and sends it to A via the Peras cert diffusion channel.
6. A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
7. A calls `addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message.
8. `chainSelSync` triggers `chainSelectionForBlock` for F. The fork fragment now has `wsvTotalWeight = H + 15`, beating the honest chain's `wsvTotalWeight = H + 0`.
9. Node A switches to the adversarial fork F, rolling back the honest chain tip.

The root cause is confirmed at: [1](#0-0)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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
