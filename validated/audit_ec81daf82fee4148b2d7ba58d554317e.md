### Title
Peras Certificate Validation Bypass Allows Arbitrary Certificate Injection via Object Diffusion Mini-Protocol — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic or structural validation. An unprivileged peer can send a crafted `PerasCert` over the Peras certificate diffusion mini-protocol; the certificate will pass "validation," be stored in the `PerasCertDB`, and trigger chain-selection side-effects that boost an attacker-chosen block.

---

### Finding Description

`validatePerasCert` in the catch-all `instance StandardHash blk => BlockSupportsPeras blk` is a stub that always returns `Right`:

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

No signature, quorum, round-number, or boosted-block-point check is performed. The `PerasValidationErr` data type is also a single-constructor stub with no fields, so there is no error vocabulary to enforce:

```haskell
data PerasValidationErr blk
  = PerasValidationErr
  deriving stock (Show, Eq)
``` [2](#0-1) 

This stub instance is the **only** instance in the repository (the `-- TODO: degenerate instance for all blks` comment confirms it is used universally): [3](#0-2) 

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [4](#0-3) 

`processCerts` then stores every certificate that passes (i.e., every certificate) and triggers `ChainDB.addPerasCertAsync`, which feeds into chain selection: [5](#0-4) 

The same pattern applies to `validatePerasVote`, which only checks stake-distribution membership but never verifies the vote's cryptographic signature, allowing any peer that knows a valid voter ID to forge votes for arbitrary blocks: [6](#0-5) 

---

### Impact Explanation

Peras certificates are the mechanism by which the Peras protocol boosts a block's weight in chain selection. A node that accepts a forged certificate for an attacker-chosen block will treat that block as having additional weight, potentially switching to a non-canonical chain. Because `validatePerasCert` never rejects any certificate, an unprivileged peer can:

1. Inject a certificate claiming any `PerasRoundNo` and any `Point blk` as the boosted block.
2. Have that certificate stored durably in the `PerasCertDB` and acted upon by chain selection.
3. Cause the honest node to prefer a chain the attacker controls, bypassing the honest-majority assumption that Peras is designed to enforce.

This matches the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*, and also the **Medium** category: *miniprotocol flaw that materially weakens certificate authorization*.

---

### Likelihood Explanation

The attack requires only a network connection to a running node. The Peras certificate diffusion mini-protocol is an externally reachable surface. No keys, stake, or privileged access are needed. The attacker only needs to construct a `PerasCert` record with the desired `pcCertRound` and `pcCertBoostedBlock` fields and send it over the wire. The stub validation will accept it unconditionally.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies: (a) the certificate's aggregate BLS/vote signature against the claimed voter set, (b) that the voter set meets the quorum threshold, (c) that the boosted block point is a known block on a valid chain, and (d) that the round number is within the expected window.
2. Replace the stub `validatePerasVote` with an implementation that verifies the per-vote cryptographic signature before accepting the vote into the pool.
3. Until real validation is implemented, the mini-protocol handler should refuse all inbound certificates and votes rather than accepting them unconditionally.
4. Track this under the existing issue referenced in the TODO comments (`https://github.com/tweag/cardano-peras/issues/120`), but treat it as a security-blocking item rather than a deferred feature.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Unprivileged peer
  → Peras cert diffusion mini-protocol (ObjectDiffusion server)
  → makePerasCertPoolWriterFromChainDB  [PerasCert.hs:118]
      opwAddObjects = processCerts ... (validatePerasCert mkPerasParams) ...
  → processCerts  [PerasCert.hs:164]
      validateCert cert  -- calls validatePerasCert
  → validatePerasCert params cert  [SupportsPeras.hs:353]
      = Right (ValidatedPerasCert cert ...)   -- ALWAYS succeeds
  → addCert (WithArrivalTime now validatedCert)
  → ChainDB.addPerasCertAsync chainDB cert
  → chain selection: boosted block = attacker-supplied pcCertBoostedBlock
```

A crafted certificate with `pcCertBoostedBlock = <attacker's block point>` and any `pcCertRound` passes all checks and is stored as a `ValidatedPerasCert`, causing the node's chain selection to apply a Peras boost to the attacker's chosen block. [7](#0-6) [1](#0-0)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-342)
```haskell
  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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
