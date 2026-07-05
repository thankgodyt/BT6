### Title
Peras Certificate and Vote Validation Universally Bypassed via Degenerate `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type class defines the interface for validating Peras certificates and votes. A universal degenerate instance (`instance StandardHash blk => BlockSupportsPeras blk`) is installed for all block types. This instance's `validatePerasCert` unconditionally returns `Right` (success) without performing any cryptographic or protocol-level checks, and `validatePerasVote` skips all validation beyond a stake-distribution lookup. Both production certificate-ingestion paths (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub validator. An unprivileged peer can therefore submit arbitrarily crafted Peras certificates that are accepted and stored without any verification, directly influencing chain selection via the Peras boost mechanism.

---

### Finding Description

**Root cause — `SupportsPeras.hs`, the degenerate universal instance:**

The `BlockSupportsPeras` class declares two critical validation methods:

```haskell
validatePerasCert ::
  PerasCfg blk -> PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only instance in the codebase is the catch-all degenerate one:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing is in place.
  getPerasCertInBlock _ = Nothing
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

`validatePerasCert` performs **zero** checks: no cryptographic signature verification, no round-number bounds check, no quorum proof, no issuer eligibility check. It wraps the raw, unverified `PerasCert` directly into a `ValidatedPerasCert` and assigns it the full `perasWeight` boost.

`validatePerasVote` performs only a stake-distribution lookup (confirming the voter ID exists in the distribution map) but skips all cryptographic verification of the vote's authenticity.

**Production call sites — `PerasCert.hs`:**

Both production object-pool writers call this stub validator directly:

```haskell
makePerasCertPoolWriterFromCertDB ... =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams)   -- ← degenerate stub
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , ...
    }

makePerasCertPoolWriterFromChainDB ... =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← degenerate stub
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , ...
    }
``` [5](#0-4) [6](#0-5) 

Certificates that pass `validatePerasCert` (which is every certificate, unconditionally) are persisted to `PerasCertDB` or submitted to `ChainDB` via `addPerasCertAsync`. Once in `ChainDB`, the `vpcCertBoost = perasWeight params` value is applied during chain selection, causing the node to prefer the boosted block's chain over competing candidates.

**Attacker-controlled entry path:**

The Peras certificate object-diffusion mini-protocol is a peer-facing network protocol. An unprivileged peer connecting to a node can submit a `PerasCert` message claiming to certify any `(round, block-point)` pair. The message is received, deserialized, and passed to `opwAddObjects`, which calls `processCerts` → `validatePerasCert` → unconditional `Right` → stored and applied to chain selection.

---

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate verification enabling unauthorized chain-selection manipulation.**

A malicious peer with no privileged keys can:

1. Forge a `PerasCert` pointing to any block on any fork (including an adversarial minority chain).
2. Submit it via the object-diffusion protocol to an honest node.
3. The certificate passes `validatePerasCert` unconditionally and is stored with full `perasWeight` boost.
4. Chain selection now treats the adversary's target block as having a Peras certificate, making the node prefer that chain over the canonical chain — even if the canonical chain is longer or has more honest stake behind it.

This directly satisfies the **Critical** impact category: *"Bypass of … certificate/signature validation … that enables unauthorized … certificate acceptance"* and the **High** category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The Peras boost is specifically designed to make certified chains strongly preferred. Bypassing the certification check inverts this security property: the boost mechanism becomes an attack vector rather than a safety guarantee.

---

### Likelihood Explanation

**High.** The entry point is the standard peer-to-peer object-diffusion protocol, reachable by any node that can establish a connection. No keys, stake, or privileged access are required. The attacker only needs to craft a valid CBOR-encoded `PerasCert` message (a two-field structure: `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`) and send it. The degenerate instance is the only instance in the codebase, so there is no code path that performs real validation. The TODOs confirm this is a known gap, not an accidental omission.

---

### Recommendation

1. Implement a real `BlockSupportsPeras` instance for Cardano blocks (replacing the degenerate catch-all) that performs full cryptographic verification of `PerasCert` and `PerasVote` objects: quorum proof, issuer eligibility, round-number bounds, and KES/VRF signatures as specified by the Peras protocol.
2. Until a real instance is available, the object-diffusion inbound handler for Peras certificates should reject all inbound certificates at the network boundary rather than passing them through a stub validator that always succeeds.
3. `getPerasCertInBlock` must be implemented to extract and re-validate certificates embedded in blocks during block application, ensuring consistency between the diffusion path and the ledger path.

---

### Proof of Concept

**Attacker steps (private testnet):**

1. Start a node running the Peras-enabled consensus code.
2. Connect a malicious peer via the object-diffusion mini-protocol.
3. Construct a `PerasCert` CBOR payload:
   - `pcCertRound`: any round number (e.g., current round)
   - `pcCertBoostedBlock`: the `Point` of a block on an adversarial fork
4. Send the certificate to the honest node.
5. Observe via tracing that `processCerts` accepts the certificate (no `PerasCertValidationError` is thrown).
6. Observe that `ChainDB` now treats the adversarial fork's tip as having a Peras boost, causing chain selection to prefer it over the canonical chain.

**Code confirmation:**

`validatePerasCert` at lines 353–358 of `SupportsPeras.hs` contains no conditional logic — it is a single unconditional `Right` expression. There is no code path reachable from `processCerts` that can reject a certificate on cryptographic grounds. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
