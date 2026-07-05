### Title
Peras Certificate Validation Bypass: `validatePerasCert` Stub Unconditionally Accepts All Inbound Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation. The production inbound-certificate pipeline (`processCerts`) calls this stub with a placeholder `mkPerasParams` argument instead of ledger-derived Peras configuration. As a result, any unprivileged peer can send arbitrarily crafted Peras certificates that pass "validation" and are durably stored in the `PerasCertDB`, where they influence chain selection via Peras weight boosts.

---

### Finding Description

**Analog to the external report:** In the IonZapper bug, `zapRepay` wrapped ETH into WETH and then called `repay` with the wrong `payer` argument (`msg.sender` instead of `address(this)`), so the wrong source was used for the state-changing operation. Here, `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` call `processCerts` with `validatePerasCert mkPerasParams` as the validation function — but `mkPerasParams` is a placeholder and `validatePerasCert` is a stub that ignores the certificate entirely and always returns `Right`. The wrong (no-op) validation function is passed to the operation that gates certificate acceptance, so the wrong source of truth (nothing) is used to authorize a consensus-state-changing operation.

**Root cause — `validatePerasCert` stub:**

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

This is the **default instance** for all `StandardHash blk`, meaning it applies to every concrete block type in the system. [1](#0-0) 

**Root cause — placeholder params passed in production pool writers:**

`makePerasCertPoolWriterFromCertDB` passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` does the same: [3](#0-2) 

**The `processCerts` gate that relies on this validation:**

`processCerts` calls `validateCert` on each inbound certificate and only rejects the batch if any call returns `Left`. Since `validatePerasCert` always returns `Right`, the gate never fires:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Accepted certificates are added to the `PerasCertDB` via `addPerasCertAsync`, which enqueues a chain-selection event: [5](#0-4) 

The `PerasCertDB` weight snapshot is then consumed by chain selection to boost the weight of the certified block: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for any arbitrary block (any `pcCertRound`, any `pcCertBoostedBlock`) and send it via the Peras certificate ObjectDiffusion mini-protocol. Because `validatePerasCert` never rejects anything, the certificate is stored in the `PerasCertDB` and its weight boost is applied during chain selection. This allows a peer with zero stake to:

1. Boost a non-canonical or adversarial chain fragment, causing an honest node to prefer it over the honest chain.
2. Inject certificates for past rounds to retroactively alter the weight of already-seen chains.

This maps to the **High** impact class: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*, and to the **Critical** class: *Bypass of Peras certificate checks that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

The attack requires only network access. Any peer connected via the Peras certificate diffusion mini-protocol can send a crafted certificate. No key material, stake, or privileged access is needed. The code path is exercised whenever a certificate is received from a peer, making this reachable in any deployment where the Peras certificate diffusion layer is active.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs full cryptographic and structural validation of the certificate (BLS aggregate signature over the correct message, valid round number, valid boosted block reference, quorum threshold, voter eligibility). Until that is in place, the `processCerts` inbound pipeline should refuse all certificates rather than accept them unconditionally. The placeholder `mkPerasParams` argument must also be replaced with the actual Peras configuration derived from the current ledger state.

---

### Proof of Concept

1. Connect to a target node that has the Peras certificate ObjectDiffusion mini-protocol active.
2. Construct a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on a minority fork.
3. Send the certificate via the mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally. [7](#0-6) 
5. The certificate is added to the `PerasCertDB` via `addCert`.
6. `implGetWeightSnapshot` returns a weight snapshot that includes the boost for the attacker-chosen block. [8](#0-7) 
7. Chain selection uses this snapshot to prefer the boosted (adversarial) chain over the honest chain, causing the node to switch to a non-canonical fork. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```
