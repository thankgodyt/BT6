### Title
Unvalidated Peras Certificate Acceptance Enables Unprivileged Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, meaning every inbound `PerasCert` received from any peer is accepted without any cryptographic or semantic check. Because `processCerts` (the ObjectDiffusion inbound handler) feeds peer-supplied certificates directly through this no-op validator and then stores them via `addCert`, any unprivileged peer can inject a crafted certificate whose `pcCertBoostedBlock` points to an arbitrary block. The stored certificate carries the full `perasWeight` boost and is consumed by chain selection via `PerasWeightSnapshot`, potentially causing the node to prefer a non-canonical adversarial fork over the honest chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

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

This is the catch-all instance for **all** block types: [2](#0-1) 

No BLS aggregate-signature check, no committee-membership check, no round-number bounds check, and no `pcCertBoostedBlock` existence check is performed. The returned `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params` — the full configured Peras weight boost.

**Inbound path — `processCerts` stores every accepted certificate:** [3](#0-2) 

`processCerts` receives a `validateCert` callback (bound to `validatePerasCert` in production), filters only certificates whose round is not already in the DB, calls `validateCert` on each, and on an all-`Right` result calls `addCert` for every certificate. Because `validatePerasCert` always returns `Right`, the filter is the only gate — and it only deduplicates by `PerasRoundNo`, not by content.

**Chain-selection sink — injected certificate triggers fork switch:** [4](#0-3) 

`addPerasCertAsync` stores the certificate and, per its own documentation, "if this leads to a fork to be weightier than our current selection, this will trigger a fork switch." The weight snapshot is consumed by `compareChainDiffs` during candidate sorting: [5](#0-4) 

**Exploit path:**

1. Attacker connects to the target node as a normal peer and negotiates the ObjectDiffusion miniprotocol.
2. Attacker crafts a `PerasCert` with `pcCertRound` set to a round not yet in the DB and `pcCertBoostedBlock` pointing to a block on an adversarial fork (which may already be in the VolatileDB, or will arrive shortly).
3. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The certificate is stored with `vpcCertBoost = perasWeight params`.
5. `addPerasCertAsync` updates the `PerasWeightSnapshot`; the adversarial block now carries a full Peras weight boost.
6. On the next chain-selection run, `compareChainDiffs` sorts the adversarial candidate above the honest chain, and the node switches to the adversarial fork.

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker with only a normal peer connection can cause an honest node to prefer a non-canonical, adversarially-constructed chain over the honest chain. This violates the Peras weight-boost security assumption, which requires that only certificates produced by a legitimate quorum of committee members can boost a block. The missing validation removes that guarantee entirely: a single peer with zero stake can forge the effect of a quorum certificate.

This falls under: *"High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**High.** The ObjectDiffusion miniprotocol is reachable by any peer that can establish a node-to-node connection. No stake, no committee membership, no key material, and no privileged role is required. The attacker only needs to know a block hash on an adversarial fork (trivially obtained by observing the network or constructing a fork). The attack is deterministic and requires a single well-formed CBOR-encoded `PerasCert` message.

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that performs, at minimum:

1. **BLS aggregate-signature verification** over `(pcRoundNo, pcBoostedBlock)` against the aggregate public key derived from the declared voter set.
2. **Committee-membership and eligibility-proof verification** for each voter in `pcVoters` (persistent voters via stake snapshot; non-persistent voters via their VRF eligibility proofs).
3. **Quorum-threshold check**: the declared voters must collectively hold stake above the configured quorum threshold.
4. **Round-number bounds check**: `pcCertRound` must be within the acceptable window relative to the current chain tip.
5. **`pcCertBoostedBlock` existence/ancestry check**: the boosted block must be a known, non-invalid block that is a descendant of the immutable tip.

Until a real implementation is in place, the `processCerts` handler should reject all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.

### Proof of Concept

```
-- Attacker constructs and sends via ObjectDiffusion:
craftedCert :: PerasCert blk
craftedCert = PerasCert
  { pcCertRound        = <any round not yet in DB>
  , pcCertBoostedBlock = <Point of adversarial block on fork>
  }

-- processCerts calls:
validatePerasCert params craftedCert
-- => Right (ValidatedPerasCert { vpcCert = craftedCert
--                               , vpcCertBoost = perasWeight params })
-- No signature, no committee check, no quorum check performed.

-- addCert stores the ValidatedPerasCert.
-- addPerasCertAsync triggers chain selection.
-- compareChainDiffs now ranks the adversarial fork above the honest chain.
-- Node switches to adversarial fork.
``` [1](#0-0) [6](#0-5) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-321)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1142-1144)
```haskell
  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```
