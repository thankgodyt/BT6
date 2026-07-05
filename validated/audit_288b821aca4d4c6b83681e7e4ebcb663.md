### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unauthorized Chain Boost by Any Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Because `processCerts` in the object-diffusion layer feeds this stub directly as the validation gate for peer-supplied certificates, any unprivileged peer can inject an arbitrary `PerasCert` that will be accepted, stored in the `PerasCertDB`, and used to trigger chain selection for the boosted block — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate that must reject structurally or cryptographically invalid certificates before they enter the node's storage and chain-selection pipeline. The universal instance that covers all block types implements this gate as a no-op stub:

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

Every certificate, regardless of its content, is wrapped in `Right` and assigned the full `perasWeight` boost. No signature, quorum proof, round-number range, boosted-block existence, or committee-membership check is performed.

This stub is wired directly into the production inbound path. `makePerasCertPoolWriterFromChainDB` — the writer used for peer-received certificates — passes `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` and, when the error list is empty (which it always is), calls `addCert` for every certificate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never produces a `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is unconditionally added to the `PerasCertDB` and forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message.

`chainSelSync` then processes the certificate: it stores it in the `PerasCertDB` and, if the boosted block is present in the `VolatileDB`, immediately calls `chainSelectionForBlock` for that block, re-running chain selection with the certificate's boost weight applied:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The analog to the external report is exact: just as `openTrade` silently accepts ETH sent under the wrong `_type` condition instead of reverting, `validatePerasCert` silently accepts every certificate under every condition instead of rejecting invalid ones. In both cases the "wrong" input is consumed and acted upon rather than discarded with an error.

---

### Impact Explanation

A Peras certificate carries a `perasWeight` boost (default: 15 blocks) that is added to the chain density of the block it references during `preferAnchoredCandidate` / `compareAnchoredFragments`. An attacker who can inject a certificate boosting a block on a minority fork can cause an honest node to switch to that fork, violating chain-selection safety. Because the boost is large relative to normal chain growth, a single crafted certificate can flip the preferred chain without the attacker controlling any stake or keys.

This is a bypass of Peras certificate verification — an unprivileged peer can make an honest node accept an unauthorized certificate and prefer a non-canonical chain, matching the **Critical** impact class: *Bypass of certificate/vote verification checks that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer. No authentication, stake ownership, or key material is required to send a `PerasCert` message. The attacker only needs to craft a `PerasCert` with a valid CBOR encoding (round number + block point) and send it. The stub validation guarantees acceptance. Likelihood is **High** for any deployment where the Peras object-diffusion protocol is active.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check that verifies at minimum:

1. The certificate's round number is within the valid window (not expired, not from the future).
2. The boosted block's slot satisfies `perasBlockMinSlots`.
3. The certificate carries a valid aggregate signature or quorum proof from the elected committee for that round.
4. The boosted block hash is a known, non-genesis point.

Until the full cryptographic validation is available, the stub should at minimum enforce the structural/temporal invariants so that certificates with obviously invalid round numbers or genesis-point boosts are rejected before entering the `PerasCertDB`.

---

### Proof of Concept

On a private testnet with Peras object diffusion enabled:

1. Connect a malicious peer to an honest node.
2. Craft a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point of a block on a minority fork>`.
3. Send the certificate via the Peras cert object-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = PerasWeight 15}` unconditionally.
5. `ChainDB.addPerasCertAsync` enqueues `ChainSelAddPerasCert`.
6. `chainSelSync` stores the cert and calls `chainSelectionForBlock` for the boosted block.
7. `preferAnchoredCandidate` now sees the minority fork's block with +15 weight, causing the node to switch to the minority fork.

The root cause is entirely in the stub at: [5](#0-4) 

called unconditionally from the production inbound path at: [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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
