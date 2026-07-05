### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate without performing any cryptographic or semantic check. Because this is the only instance in the codebase and it is a catch-all (`instance StandardHash blk => BlockSupportsPeras blk`), every block type, including the Cardano block, inherits it. An unprivileged peer connected via the Peras object-diffusion mini-protocol can therefore inject arbitrary `PerasCert` objects that are stored in the `PerasCertDB` and immediately used to boost chain-selection weight, causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

The degenerate `BlockSupportsPeras` instance, explicitly marked as a placeholder, implements certificate validation as:

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

This is the **only** `BlockSupportsPeras` instance in the entire codebase. A `grep` across all `.hs` files confirms it is defined only in `SupportsPeras.hs` and referenced in test files — no concrete Cardano-block override exists. [2](#0-1) 

**Attacker-controlled entry path — Peras object diffusion:**

`makePerasCertPoolWriterFromChainDB` wires the inbound certificate handler for the Peras object-diffusion mini-protocol. It passes `validatePerasCert mkPerasParams` — the always-`Right` function — as the validator:

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

`processCerts` calls `validateCert` on each received certificate and, if all pass (which they always do), adds them via `addCert`: [4](#0-3) 

**Privileged downstream effect — chain selection:**

`chainSelSync` processes each newly added certificate. It reads the `pcCertBoostedBlock` field from the attacker-supplied cert, looks up the corresponding header in the `VolatileDB`, and triggers `chainSelectionForBlock` for it:

```haskell
boostedHdr <-
  lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
    Nothing -> ...
    Just boostedHdr -> pure boostedHdr
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The `PerasWeightSnapshot` used during chain comparison is built directly from the stored (unvalidated) certificates: [6](#0-5) 

Chain selection then compares fragments using `wsvTotalWeight`, which sums block number and the attacker-injected weight boost: [7](#0-6) 

**Exploit flow:**

1. Attacker connects to a node as a Peras object-diffusion peer.
2. Attacker sends a `PerasCert` with `pcCertBoostedBlock` pointing to any block hash present in the target node's `VolatileDB` (learnable via ChainSync).
3. `processCerts` calls `validatePerasCert`, which unconditionally returns `Right`.
4. The certificate is stored in `PerasCertDB` with the attacker-chosen boost weight (`perasWeight params`).
5. `chainSelSync` triggers chain selection for the boosted block.
6. The node's `WeightedSelectView` now assigns inflated weight to the attacker-chosen fork, potentially causing it to be preferred over the honest chain.

---

### Impact Explanation

**Severity: High — chain selection manipulation.**

An unprivileged peer can cause an honest node to prefer a non-canonical chain by injecting fake Peras certificates that artificially inflate the weight of any block in the node's `VolatileDB`. Because `perasWeight` can be set to a large value and there is no bound on how many certificates an attacker can inject per round (only one per `PerasRoundNo` is deduplicated), the attacker can accumulate enough synthetic weight to override the honest chain's length advantage. This directly violates the Peras chain-selection security assumption that only legitimately certified blocks receive weight boosts.

---

### Likelihood Explanation

Peras is disabled by default on Cardano mainnet but is the active development target and is enabled in private testnets. The object-diffusion mini-protocol is already wired and reachable from any connected peer. No keys, stake, or operator privileges are required — only a TCP connection to a node with Peras enabled. The attack is deterministic and requires no brute force.

---

### Recommendation

Replace the placeholder `validatePerasCert` implementation with a real check that verifies:
1. The certificate's aggregate BLS signature over the election ID and vote candidate against the aggregated public keys of the claimed committee members.
2. That the claimed committee members are eligible (stake-weighted sortition check) for the stated round.
3. That the quorum threshold is met.

Until the real implementation is in place, the `processCerts` inbound handler should reject all certificates (return `Left`) rather than accept all of them, so that the placeholder cannot be exploited.

---

### Proof of Concept

```
Attacker node A connects to honest node H via the Peras object-diffusion protocol.

1. A learns block hash B_adv from H's ChainSync tip (a block on a minority fork
   present in H's VolatileDB).

2. A sends:
     PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = B_adv }

3. H calls validatePerasCert, which returns Right unconditionally.

4. H stores the cert; PerasWeightSnapshot now maps B_adv -> perasWeight.

5. chainSelSync triggers chainSelectionForBlock for B_adv.

6. WeightedSelectView for the fork containing B_adv now has
     wsvTotalWeight = blockNo + perasWeight  (e.g., blockNo + 1000)
   which exceeds the honest chain's wsvTotalWeight = blockNo + 0.

7. H switches to the minority fork.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-531)
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
