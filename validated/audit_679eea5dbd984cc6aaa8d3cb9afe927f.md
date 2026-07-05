### Title
Peras Certificate Validation Unconditionally Accepts Any Forged Certificate Without Cryptographic Verification — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the catch-all `BlockSupportsPeras` instance unconditionally returns `Right` for every incoming Peras certificate, performing zero cryptographic or eligibility checks. Because this is the only instance wired into the production certificate-ingestion pipeline, any unprivileged peer can send a crafted `PerasCert` that boosts an arbitrary block, causing the receiving node to inflate that block's chain-selection weight and potentially switch to a non-canonical fork.

---

### Finding Description

**Root cause — stub validation that omits all checks**

`validatePerasCert` is declared in the `BlockSupportsPeras` class as the gate that must verify a certificate before it is stored. The sole concrete instance is:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

Every certificate, regardless of content, is accepted and assigned the full configured boost weight. No aggregate-signature check, no committee-membership check, no quorum check is performed.

**Production ingestion path**

`makePerasCertPoolWriterFromChainDB` wires this stub directly into the live certificate-diffusion pipeline:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)   -- ← always Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions results into valid/invalid; because `validatePerasCert` never returns `Left`, every certificate clears the filter and is forwarded to `ChainDB.addPerasCertAsync`.

**How accepted certificates affect chain selection**

Once stored, `implGetWeightSnapshot` builds the `PerasWeightSnapshot` from every certificate in `pcdsCertsByTicket`:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
``` [3](#0-2) 

`chainSelectionForBlock` reads this snapshot atomically and uses it to compare candidate chains:

```haskell
(invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [4](#0-3) 

`weightedSelectView` then computes `wsvTotalWeight = blockNo + weightBoostOfFragment`, and `preferCandidate` switches to any candidate whose total weight exceeds the current chain's:

```haskell
preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch ...
``` [5](#0-4) 

**Exploit path (step by step)**

1. Attacker identifies a minority-fork block `B` at block number `N` on a chain that is currently shorter than the honest chain (block number `M`, `N < M`).
2. Attacker crafts `PerasCert { pcCertRound = r, pcCertBoostedBlock = B }` with an arbitrary round number and sends it to an honest node via the ObjectDiffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
4. The certificate is stored; `implGetWeightSnapshot` now includes `(B, perasWeight)` in the snapshot.
5. When the attacker's minority-fork block arrives, `chainSelectionForBlock` reads the snapshot. The minority fork's total weight becomes `N + perasWeight`; if `N + perasWeight > M`, `preferCandidate` returns `ShouldSwitch`.
6. The honest node rolls back to the minority fork.

The attacker needs no keys, no stake, and no privileged access — only the ability to send a network message.

---

### Impact Explanation

This is a **critical bypass of Peras certificate validation**. An unprivileged peer can cause an honest node to prefer a non-canonical chain by injecting a forged certificate. Because the boost weight can be configured to be large (e.g., `perasWeight params` on mainnet is intended to be ~15 block-equivalents), a single forged certificate can overcome a deficit of up to that many blocks, enabling a chain-selection attack without requiring a stake majority. This directly violates the Peras security property that only legitimately certified blocks receive weight boosts.

---

### Likelihood Explanation

The attack surface is the ObjectDiffusion mini-protocol, which is reachable by any peer the node connects to. No special privileges, keys, or resources are required beyond the ability to open a connection and send a well-formed CBOR-encoded `PerasCert`. The stub is the only instance in the codebase; there is no override for Cardano-specific block types.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS/KES signature over the certificate body against the claimed committee members' public keys.
2. Checks that each claimed voter holds a valid eligibility proof (VRF output within the committee-selection threshold) for the given round.
3. Verifies that the accumulated vote stake meets the configured quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
4. Checks that the boosted block's slot falls within the valid range for the claimed round.

Until a real implementation is available, the node should refuse to process any incoming Peras certificates (return `Left` unconditionally) rather than accept them all.

---

### Proof of Concept

```
-- Pseudocode: attacker sends a crafted certificate to an honest node
let forgery = PerasCert
      { pcCertRound     = PerasRoundNo 42          -- arbitrary round
      , pcCertBoostedBlock = minorityForkBlockPoint -- block on a shorter fork
      }
-- Send forgery via ObjectDiffusion cert-diffusion channel to honest node.
-- processCerts calls (validatePerasCert mkPerasParams forgery)
-- → always returns Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
-- → stored in PerasCertDB
-- → getWeightSnapshot now includes minorityForkBlockPoint with full boost
-- → next chainSelectionForBlock call may switch to the minority fork
```

The `validatePerasCert` stub is at: [6](#0-5) 

The production ingestion call site is at: [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
