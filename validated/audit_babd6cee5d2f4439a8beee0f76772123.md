### Title
Hardcoded `mkPerasParams` and Unconditional `Right` in `validatePerasCert` Allow Unprivileged Peers to Inject Arbitrary Peras Certificates into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The production Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`) calls `validatePerasCert` with a hardcoded default parameter object (`mkPerasParams`) instead of the actual node configuration, and the `validatePerasCert` implementation itself unconditionally returns `Right` for every certificate it receives. Together these two defects mean that any certificate arriving from an unprivileged peer over the object-diffusion mini-protocol is accepted without any cryptographic or structural check and is immediately stored in the `ChainDB` with a non-zero Peras boost weight, directly influencing chain selection.

---

### Finding Description

**Root cause 1 — hardcoded wrong parameter (`mkPerasParams`)**

Both production pool-writer constructors pass a compile-time constant as the `PerasCfg` argument to `validatePerasCert`:

```haskell
-- makePerasCertPoolWriterFromChainDB  (production path)
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromCertDB  (also used in production)
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`mkPerasParams` is a hard-wired default bundle (`PerasWeight 15`, quorum threshold `3/4`, etc.) that is independent of the running node's actual Peras configuration. Even if a future implementation of `validatePerasCert` were correct, it would be checking certificates against the wrong quorum threshold, wrong weight, and wrong timing parameters.

**Root cause 2 — `validatePerasCert` unconditionally returns `Right`**

The sole `BlockSupportsPeras` instance (which covers every block type including the Cardano production block) implements `validatePerasCert` as:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

No aggregate-signature check, no committee-eligibility check, no round-number sanity check, no boosted-block existence check — the function is a pure identity wrapper that stamps every certificate as valid and assigns it a boost of `perasWeight mkPerasParams = PerasWeight 15`.

**End-to-end exploit path**

1. An unprivileged peer connects via the Peras object-diffusion mini-protocol.
2. It sends a batch of `PerasCert` objects referencing any block point it chooses (e.g., a non-canonical fork tip).
3. `processCerts` calls `validatePerasCert mkPerasParams` on each certificate.
4. Every certificate returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}`.
5. Each `ValidatedPerasCert` is timestamped and stored via `ChainDB.addPerasCertAsync`.
6. Chain selection now treats the attacker-chosen block as boosted by weight 15, potentially preferring it over the honest canonical chain.

---

### Impact Explanation

**High — chain selection manipulation.**

The Peras boost is designed to make a certified block preferred over `perasWeight` additional uncertified blocks. With `PerasWeight 15`, an attacker-injected certificate makes the node treat the attacker's chosen block as if it were 15 blocks heavier than it actually is. An adversary who can send crafted certificates for a stale or minority-fork block can cause an honest node to switch away from the canonical chain, violating the chain-selection security assumption of Ouroboros Praos/Peras. This matches the allowed impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is a standard peer-to-peer channel; any connecting peer can submit certificate batches. No stake, no key material, and no privileged role is required. The two defects are both present in the same code path and neither has a compensating check elsewhere in `processCerts`. The TODO comments confirm the developers know the validation is absent, but the code is in the production source tree and the `makePerasCertPoolWriterFromChainDB` function is explicitly documented as the production path.

---

### Recommendation

1. **Replace `mkPerasParams` with the actual node `PerasCfg`** in both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`. The `PerasCfg` must be threaded from the node's `TopLevelConfig` or equivalent configuration source.

2. **Implement real cryptographic and structural validation** in `validatePerasCert`: verify the aggregate BLS/VRF committee signature, confirm the certificate's round number is within the valid window, confirm the boosted block point exists on a known chain, and check the quorum threshold against the actual stake distribution.

3. Until both fixes are in place, consider gating the Peras object-diffusion mini-protocol behind a feature flag so that certificate ingestion is disabled in production deployments where the validation is not yet complete.

---

### Proof of Concept

**Step 1.** Connect to a target node as a normal peer and initiate the Peras object-diffusion mini-protocol session.

**Step 2.** Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a minority-fork block>`. No valid aggregate signature is needed because `validatePerasCert` never checks one.

**Step 3.** Send the certificate batch. `processCerts` will call:

```haskell
validatePerasCert mkPerasParams cert
-- returns: Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })
```

**Step 4.** The certificate is stored via `ChainDB.addPerasCertAsync`. Chain selection now applies a boost of 15 to the minority-fork block, causing the node to prefer it over the honest canonical chain if the honest chain's length advantage is ≤ 15 blocks. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
