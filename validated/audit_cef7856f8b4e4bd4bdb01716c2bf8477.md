### Title
Unconditional Peras Certificate Acceptance Enables Chain-Selection Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, accepting every peer-supplied Peras certificate without any cryptographic or structural verification. Because the production object-diffusion ingest path (`processCerts` / `makePerasCertPoolWriterFromChainDB`) calls this function to gate admission into the `PerasCertDB` and subsequently into chain selection, an unprivileged peer can inject arbitrary fake certificates that boost the weight of any block it chooses, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op:**

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

This is the **universal** instance (`instance StandardHash blk => BlockSupportsPeras blk`), meaning it applies to every block type including Cardano blocks, because no more-specific instance overrides it. [2](#0-1) 

**Attacker-controlled entry path — object diffusion ingest:**

`processCerts` is the inbound handler for Peras certificates received from peers over the object-diffusion mini-protocol. It calls the supplied `validateCert` function and, if all certificates pass, stores them:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

The production writer (`makePerasCertPoolWriterFromChainDB`) passes `validatePerasCert mkPerasParams` as the validation function, with an explicit TODO acknowledging the placeholder:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [4](#0-3) 

**How accepted certificates affect chain selection:**

Once a `ValidatedPerasCert` is stored in the `PerasCertDB`, its `vpcCertBoost` (set to `perasWeight params` for every certificate, regardless of legitimacy) is incorporated into `compareAnchoredFragments` via the `PerasWeightSnapshot`. This directly influences which candidate chain the node selects. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block on an adversarial fork. Because `validatePerasCert` returns `Right` unconditionally, the certificate passes the `processCerts` gate, is stored in the `PerasCertDB`, and its boost weight is applied during chain selection. This lets the attacker make an honest node prefer a non-canonical or adversarially-controlled chain over the honest chain, violating the chain-selection security assumption of the Peras protocol extension.

**Impact class:** High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions. Also potentially Critical as a bypass of Peras certificate verification checks.

---

### Likelihood Explanation

The object-diffusion mini-protocol is a public-facing peer-to-peer channel. Any connected peer can send a batch of `PerasCert` objects. No special privileges, keys, or stake are required. The attacker only needs to be a connected peer and know the hash of a block they wish to boost. The degenerate instance is the only instance in the codebase for all block types, so there is no fallback to a correct implementation.

---

### Recommendation

Replace the unconditional `Right` in `validatePerasCert` with real cryptographic and structural validation before the Peras object-diffusion path is enabled in production. At minimum, the certificate must verify:

1. The round number is within the valid range relative to the current chain tip.
2. The boosted block hash corresponds to a known block at the correct slot.
3. The certificate carries a valid aggregate BLS signature from a quorum of eligible committee members (as defined by the Peras specification).

Until real validation is implemented, the object-diffusion ingest path for Peras certificates should be disabled or gated behind a feature flag that is off by default in production deployments. [6](#0-5) 

---

### Proof of Concept

1. Connect to a target node as a peer via the object-diffusion mini-protocol.
2. Craft a `PerasCert` value:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of adversarial block> }
   ```
3. Send it as a batch via the object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The certificate is stored in `PerasCertDB` and its boost is applied in `compareAnchoredFragments`.
6. The node now assigns extra weight to the adversarially-chosen block, potentially switching to the attacker's fork. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L114-149)
```haskell
compareAnchoredFragments cfg weights frag1 frag2
  -- Optimize the case where Peras is disabled.
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition frag1 frag2) $
        case (frag1, frag2) of
          (Empty _, Empty _) ->
            -- The fragments intersect but are equal: their anchors must be equal,
            -- and hence the fragments represent the same chain. They are therefore
            -- equally preferable.
            EQ
          (Empty anchor, _ :> tip') ->
            -- Since the fragments intersect, but the first one is empty, its anchor
            -- must lie somewhere along the the second. If it is the tip, the two
            -- fragments represent the same chain and are equally preferable. If
            -- not, the second chain is a strict extension of the first and is
            -- therefore strictly preferable.
            if blockPoint tip' == AF.castPoint (AF.anchorToPoint anchor)
              then EQ
              else LT
          (_ :> tip, Empty anchor') ->
            -- This case is symmetric to the previous
            if blockPoint tip == AF.castPoint (AF.anchorToPoint anchor')
              then EQ
              else GT
          (_ :> tip, _ :> tip') ->
            -- Case 4
            compare
              (selectView cfg (getHeader1 tip))
              (selectView cfg (getHeader1 tip'))
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
```
