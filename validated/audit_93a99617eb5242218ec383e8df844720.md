### Title
Unconditional `validatePerasCert` Acceptance Allows Unprivileged Peer to Manipulate Chain Selection via Crafted Peras Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate by returning `Right` from `validatePerasCert` without performing any cryptographic or structural checks. Because this stub is the only instance in the production codebase and is wired directly into the peer-facing certificate ingestion path, an unprivileged peer can inject an arbitrary crafted certificate, have it stored in `PerasCertDB`, and trigger chain selection with an artificial weight boost for any block the attacker chooses.

---

### Finding Description

**Root cause — always-`Right` validation stub:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

This is declared as a **catch-all instance** for every block type: [2](#0-1) 

No more-specific instance overrides it for Cardano blocks, so it is the live production code path.

**Wiring into the peer-facing ingestion path:**

`validatePerasCert mkPerasParams` is passed as the `validateCert` callback in both pool-writer constructors: [3](#0-2) [4](#0-3) 

`processCerts` calls `validateCert` on every certificate received from a peer and only rejects a batch when at least one call returns `Left`: [5](#0-4) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never reached; every certificate from every peer is unconditionally accepted.

**Chain-selection side-effect:**

Once accepted, the certificate is stored in `PerasCertDB` and `chainSelSync` immediately triggers chain selection for the boosted block: [6](#0-5) 

The weight snapshot read during `constructPreferableCandidates` and `preferAnchoredCandidate` now includes the attacker-supplied boost: [7](#0-6) 

**Analog to the original report:**

The original bug had a guard that should have been `A && B` but was implemented so that the operation succeeded when only one condition held. Here the guard is `validatePerasCert` which should check *both* (a) that the certificate's cryptographic proof is valid *and* (b) that the claimed boosted block and round are consistent with the ledger state — but instead it checks *neither*, unconditionally returning success.

---

### Impact Explanation

**Severity: High — chain-selection manipulation by an unprivileged peer.**

An attacker who can connect to a node (no credentials required) can:

1. Craft a `PerasCert` naming any block hash present in the node's VolatileDB as `pcCertBoostedBlock`.
2. Send it via the object-diffusion mini-protocol.
3. The certificate passes `validatePerasCert` unconditionally and is stored.
4. Chain selection is re-run with the artificial `perasWeight` boost applied to the attacker-chosen block.
5. If the attacker also serves a chain containing that block, the node may switch to a non-canonical fork that it would otherwise reject under pure Praos chain selection.

This matches the allowed impact: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Medium-High.** The object-diffusion mini-protocol for Peras certificates is reachable by any peer that speaks the negotiated protocol version. No stake, keys, or prior authentication is required. The only practical constraint is that the boosted block must already be in the node's VolatileDB; an attacker who also controls a block-producing node (or who can predict which blocks will be downloaded) can satisfy this trivially. The TODO comment and linked issue (`cardano-peras#120`) confirm the stub is intentional but unfinished, meaning the window is open for the entire lifetime of any deployment that enables the Peras object-diffusion protocol.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that verifies:

1. The aggregate vote signature over `(electionId, candidate)` using the committee's aggregate verification key.
2. VRF outputs for non-persistent committee members.
3. That the claimed `pcCertRound` and `pcCertBoostedBlock` are consistent with the ledger's Peras parameters (round boundaries, cooldown rules, etc.).

Until the real implementation is ready, the object-diffusion certificate ingestion path should be disabled or gated behind a feature flag so that no peer-supplied certificate can influence chain selection.

---

### Proof of Concept

```
1. Node A (victim) has block B (hash H) in its VolatileDB.
2. Attacker peer connects to Node A via the object-diffusion mini-protocol.
3. Attacker sends:
     PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = Point { slot = s, hash = H } }
4. processCerts calls validatePerasCert mkPerasParams cert
   => always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })
5. Certificate is stored in PerasCertDB; getWeightSnapshot now returns a snapshot
   that assigns weight boost W to block H.
6. chainSelSync triggers chainSelectionForBlock for H.
7. constructPreferableCandidates calls preferAnchoredCandidate with the boosted
   weight snapshot; any candidate chain containing H now has total weight
   increased by W, potentially making it preferred over the honest chain.
8. Node A switches to the attacker's fork.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L119-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L776-778)
```haskell
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```
