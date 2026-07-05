### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production default instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound certificate without performing any cryptographic, committee-membership, or structural check. This stub is wired directly into the live `PerasCertDiffusion` mini-protocol handler (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer connected over `NodeToNodeV_16` can therefore inject arbitrarily crafted Peras certificates that are stored in `PerasCertDB` and fed into `chainSelectionForBlock`, allowing the attacker to add artificial boost weight to any block in the VolatileDB and steer the node toward a non-canonical chain.

### Finding Description

**Root cause — unconditional `Right` in the default `validatePerasCert` implementation:**

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

This is the **only** instance of `BlockSupportsPeras` in the codebase (a catch-all `instance StandardHash blk => BlockSupportsPeras blk`), so it is the instance used for every concrete block type, including Cardano blocks. [2](#0-1) 

**Production call site — `makePerasCertPoolWriterFromChainDB`:**

The production writer for the `PerasCertDiffusion` mini-protocol passes this stub directly as the validator:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

**`processCerts` accepts every certificate that passes `validateCert`:** [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every certificate in every batch is forwarded to `ChainDB.addPerasCertAsync`.

**Chain-selection side-effect — `chainSelSync`:**

When a certificate is added asynchronously, `chainSelSync` processes it. If the boosted block is present in the VolatileDB, it immediately triggers `chainSelectionForBlock` for that block, using the injected boost weight:

```haskell
boostedHdr <-
  lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
    Nothing -> idExitEarly $ addedCertRes
    Just boostedHdr -> pure boostedHdr
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The boost weight assigned to every accepted certificate is `perasWeight mkPerasParams` — a fixed positive value — regardless of whether the certificate was legitimately produced by a quorum of committee members.

**Mini-protocol is live in production:**

The `PerasCertDiffusion` mini-protocol is wired into the node-to-node handler stack for `NodeToNodeV_16`: [6](#0-5) [7](#0-6) 

### Impact Explanation

An unprivileged peer can:

1. Connect to a victim node over `NodeToNodeV_16`.
2. Send a batch of crafted `PerasCert` objects, each specifying an arbitrary `pcCertRound` and a `pcCertBoostedBlock` pointing to any block hash the attacker knows is in the victim's VolatileDB (learnable via ChainSync).
3. Every certificate passes `validatePerasCert` unconditionally and is stored in `PerasCertDB`.
4. For each certificate whose boosted block is present, `chainSelectionForBlock` is triggered with the artificial boost weight added to that block's chain.
5. By injecting one certificate per Peras round for a competing fork, the attacker accumulates enough artificial boost weight to make the competing chain appear heavier than the canonical chain, causing the victim node to switch away from the canonical chain.

**Impact category:** High — chain selection manipulation by an unprivileged peer, causing an honest node to prefer a non-canonical or adversarially-controlled chain beyond the intended security assumptions of Ouroboros Praos/Peras.

### Likelihood Explanation

- **Attacker preconditions:** None beyond a standard node-to-node connection over `NodeToNodeV_16`. No keys, no stake, no privileged access required.
- **Reachability:** The `PerasCertDiffusion` inbound handler is active for every peer that negotiates `NodeToNodeV_16`. The attack is fully automated and requires only knowledge of block hashes on competing forks (available via ChainSync).
- **Constraint:** The boosted block must exist in the victim's VolatileDB. This is easily satisfied by first diffusing the competing block via BlockFetch.

### Recommendation

Replace the unconditional stub with a real implementation of `validatePerasCert` that verifies:

1. The certificate carries a valid aggregate BLS/committee signature over `(electionId, candidate)`.
2. Each claimed voter is a member of the committee for the certificate's round (verified against the ledger's stake distribution and VRF-based committee selection).
3. The aggregate stake of the voters meets the quorum threshold defined in `PerasCfg`.
4. The boosted block's slot falls within the valid Peras window for the certificate's round.

Until the real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

### Proof of Concept

**Attacker steps:**

1. Connect to victim node, negotiate `NodeToNodeV_16`.
2. Via ChainSync, learn the hash `H` of a block on a competing fork that is present in the victim's VolatileDB.
3. Construct a `PerasCert` with `pcCertRound = R` (any round not yet in the victim's `PerasCertDB`) and `pcCertBoostedBlock = Point (At (Block slot H))`.
4. Send the certificate via the `PerasCertDiffusion` mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight mkPerasParams}`.
6. `ChainDB.addPerasCertAsync` is called; `chainSelSync` fires `chainSelectionForBlock` for block `H` with the injected boost.
7. Repeat for rounds `R+1, R+2, …` to accumulate boost weight until the competing chain outweighs the canonical chain.
8. The victim node switches to the attacker-boosted fork.

**Expected outcome:** The victim node's chain tip moves to the attacker-chosen fork, diverging from the canonical Cardano chain.

### Citations

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1021-1023)
```haskell
              (hPerasCertDiffusionClient version controlMessageSTM them)
          )
      return (NoInitiatorResult, trailing)
```

**File:** changelog.d/20250918_104810_thomas.bagrel_object_diffusion.md (L21-29)
```markdown
### Breaking

- Added support for `NodeToNodeV_16`
- Rely on a new version of `ouroboros-network` with support for ObjectDiffusion mini-protocol
- Modify `Ouroboros.Consensus{.Node,.Node.Tracer,.Network.NodeToNode}` to wire-in PerasCertDiffusion similarly to other mini-protocols (e.g. TX-submission)
- Add modules `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion{.Inbound,.Outbound}` with implementations of the ObjectDiffusion protocol (quite similar/inspired from TX-submission, except that client = inbound, server = outbound)
- Add module `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API` defining `ObjectPool{Reader,Writer}` interfaces, through which ObjectDiffusion accesses/stores the objects to send/that have been received.
- Add modules `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.PerasCert` and `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert` containing definitions specific to `PerasCert` diffusion through the ObjectDiffusion mini-protocol 
- Modify `Ouroboros.Consensus.Node.Serialisation` to add CBOR serialisation (`SerialiseNodeToNode`) for `Point blk`, `Tip blk`, and `PerasCert blk`
```
