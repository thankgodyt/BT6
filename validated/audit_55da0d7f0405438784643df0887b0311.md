### Title
Stub `validatePerasCert` Accepts Any Peer-Supplied `PerasCert` Without Cryptographic Validation, Enabling Fraudulent Peras Weight Boost and Chain Selection Manipulation — (`Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance for generic `blk` implements `validatePerasCert` as an unconditional stub that always returns `Right`. This stub is the sole validation gate in `processCerts`, which is wired directly into the production `PerasCertDiffusion` mini-protocol handler (`NodeToNodeV_16`). Any unprivileged peer can send a syntactically well-formed `PerasCert` (containing only a round number and a block point — no BLS aggregate signature field exists in the stub type) and cause the receiving node to accept it, store it in `PerasCertDB`, and trigger `chainSelectionForBlock` for the boosted block, potentially switching to a fraudulent fork.

---

### Finding Description

**1. The stub `validatePerasCert` always succeeds** [1](#0-0) 

The `PerasCert blk` data type in this stub instance carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — there are no BLS aggregate signature fields, no committee membership proof, and no VRF output: [2](#0-1) 

**2. `processCerts` uses this stub as the only validation gate**

`processCerts` calls `validateCert` (bound to `validatePerasCert mkPerasParams`) on each inbound cert. Since the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every cert is passed to `addCert`: [3](#0-2) 

**3. `makePerasCertPoolWriterFromChainDB` wires the stub into the production ChainDB path** [4](#0-3) 

**4. This writer is wired unconditionally into the `PerasCertDiffusion` mini-protocol handler** [5](#0-4) 

**5. `chainSelSync` triggers chain selection for the boosted block**

After the fraudulent cert is stored in `PerasCertDB`, `chainSelSync` calls `chainSelectionForBlock` for the boosted block if it is present in the VolatileDB: [6](#0-5) 

The boosted block receives `perasWeight = 15` weight units: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer connecting over `NodeToNodeV_16` can:

1. Observe valid block hashes in the VolatileDB via ChainSync (public information).
2. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on a competing fork.
3. Send it over the `PerasCertDiffusion` protocol.
4. The receiving node accepts it without any BLS signature or committee membership check, stores it in `PerasCertDB`, and triggers chain selection for the boosted block.
5. If the fork's total weight (including the fraudulent +15 boost) exceeds the current chain's weight, the node switches to the fraudulent fork.

This matches the **High** scope: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*, and also **Critical**: *bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

- The `PerasCertDiffusion` protocol is wired into the production `NodeToNode` handler unconditionally (no feature flag gates the handler itself).
- The `PerasCert blk` type has no cryptographic fields, so no forgery of keys is required — the attacker only needs to know a valid block hash (publicly available via ChainSync).
- The attack requires only a single well-formed CBOR-encoded `PerasCert` message over `NodeToNodeV_16`.
- The only partial mitigations are: (a) the boosted block must be in the VolatileDB (not yet immutable), and (b) one cert per round is accepted (duplicate suppression). Neither prevents the attack.

---

### Recommendation

1. **Immediate**: Gate `validatePerasCert` on actual BLS aggregate signature verification and committee membership proof before this code is enabled on any network. The `BLS.hs` module already defines `verifyAggregateVoteSignature` — it must be called here.
2. **Short-term**: The `PerasCert blk` stub type must include the aggregate BLS signature and VRF outputs as mandatory fields; the stub instance must not be reachable from the production diffusion path.
3. **Medium-term**: Add a feature flag that gates the `PerasCertDiffusion` handler so it is only active when the full Peras validation stack (issue [#120](https://github.com/tweag/cardano-peras/issues/120)) is complete.

---

### Proof of Concept

```haskell
-- Construct a fraudulent cert targeting a known fork block
let fraudCert = PerasCert
      { pcCertRound      = PerasRoundNo 42
      , pcCertBoostedBlock = forkBlockPoint  -- any Point blk in VolatileDB
      }

-- validatePerasCert always returns Right (stub)
case validatePerasCert mkPerasParams fraudCert of
  Right validatedCert -> putStrLn "ACCEPTED (no BLS check performed)"
  Left  _             -> putStrLn "rejected"

-- Send fraudCert over PerasCertDiffusion to target node.
-- processCerts will call addPerasCertAsync, which enqueues
-- ChainSelAddPerasCert, which calls chainSelectionForBlock
-- for forkBlockPoint with +15 weight boost.
```

The stub is confirmed as the only validation gate before `addPerasCertAsync`: [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-532)
```haskell
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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
