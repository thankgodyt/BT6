### Title
Peras Certificate Validation Unconditionally Accepts Any Crafted Certificate, Enabling Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic or eligibility checks whatsoever. Because this is the implementation wired into the live object-diffusion inbound pipeline, any unprivileged peer can send a crafted `PerasCert` for an arbitrary block, have it accepted without verification, and cause the receiving node to apply the full Peras chain-weight boost to that block during chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub wired into production:**

In `BlockSupportsPeras.hs`, the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides the following implementation:

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

Every certificate, regardless of its content, is wrapped in `Right` and assigned the full `perasWeight params` boost. No signature, no committee membership, no round-number plausibility, and no block-existence check is performed.

**Wiring into the live inbound pipeline:**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` constructs the `ObjectPoolWriter` that handles all inbound Peras certificates received from peers. It passes `validatePerasCert mkPerasParams` directly as the validation callback to `processCerts`:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
```

`processCerts` calls this callback for every certificate not already in the DB. Because the callback always returns `Right`, every new certificate passes validation and is added to the ChainDB via `ChainDB.addPerasCertAsync`.

**Chain-selection consequence:**

Each accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`. This boost is applied to the certified block's chain weight during Peras-aware chain selection. An attacker who sends a certificate for a block on a weaker fork causes the node to treat that fork as heavier than the canonical chain, potentially triggering a switch to the attacker's chosen fork.

**Analogous missing prerequisite:**

The external report's pattern is: a function calls a sub-function that requires prior authorization that was never established, causing the function to always succeed/fail incorrectly. Here, `processCerts` calls `validatePerasCert` which is supposed to enforce cryptographic prerequisites (committee membership proof, aggregate signature, round eligibility) before accepting a certificate — but those prerequisites are never checked, so the function always succeeds for any input.

---

### Impact Explanation

**Severity: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

A malicious peer can:
1. Craft a `PerasCert` for any block on any fork (including a weaker adversarial fork).
2. Send it over the Peras object-diffusion mini-protocol.
3. The receiving node accepts it unconditionally and applies the full `perasWeight` boost to that block.
4. If the boosted weight exceeds the canonical chain's weight, the node switches to the adversarial fork.

This bypasses the entire Peras committee-selection and aggregate-signature security model, reducing Peras chain-weight security to zero for any node running this code.

---

### Likelihood Explanation

Any peer that can establish a connection to the node can exploit this. No keys, no stake, no privileged access are required. The object-diffusion mini-protocol is a standard peer-to-peer channel. The only prerequisite is that Peras is active on the network, which is the intended deployment target of this code.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over the `(electionId, candidate)` pair against the committee's aggregate verification key.
2. Confirms each claimed voter is a registered committee member with non-zero stake in the relevant epoch.
3. Checks that the certified block exists and is within the valid round window.

Until the real implementation is ready, the inbound pipeline should reject all Peras certificates rather than accept them unconditionally, to avoid the chain-weight manipulation vector.

---

### Proof of Concept

**Entry path:**

1. Attacker connects to a Cardano node as a peer.
2. Attacker sends a `PerasCert` for block `B_adv` on a weaker adversarial fork via the Peras object-diffusion channel.
3. `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
4. `ChainDB.addPerasCertAsync chainDB` stores the certificate.
5. Chain selection reads the Peras boost for `B_adv` and adds `perasWeight params` to its chain weight.
6. If `weight(B_adv fork) + perasWeight > weight(canonical fork)`, the node switches to the adversarial fork.

**Key lines:** [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
