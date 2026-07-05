### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate, Enabling Chain Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right` — it performs zero cryptographic or structural checks. Any certificate received from an unprivileged peer over the ObjectDiffusion mini-protocol is accepted as "validated," stored in the `PerasCertDB`, and used to boost a block's weight in chain selection. When Peras is enabled, an attacker can fabricate certificates boosting any block in the VolatileDB, causing the node to prefer a chain it otherwise would not.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is accepted. The universal degenerate instance — explicitly marked as a temporary stub — implements this gate as:

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

This instance is declared as a universal catch-all for every `StandardHash blk` type, with no proper Cardano-specific override yet in place:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

This stub is wired directly into the production inbound certificate processing path. `processCerts` in the ObjectDiffusion pool writer calls `validatePerasCert mkPerasParams` as its validator:

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

`processCerts` partitions results into valid/invalid and throws on any invalid cert. Since `validatePerasCert` always returns `Right`, the invalid branch is never taken and every certificate — regardless of its cryptographic content — is accepted and forwarded to `addPerasCertAsync`: [4](#0-3) 

Once accepted, the certificate is stored in the `PerasCertDB` and, if the boosted block is present in the VolatileDB, chain selection is immediately re-triggered for that block: [5](#0-4) 

Chain selection uses `WeightedSelectView`, which adds `wsvWeightBoost` (derived from the `PerasWeightSnapshot`) to the block number when comparing candidates: [6](#0-5) 

The `PerasWeightSnapshot` is populated from accepted certificates via `mkPerasWeightSnapshot`, so a fabricated certificate directly inflates the weight of the attacker's chosen block. [7](#0-6) 

The test infrastructure itself acknowledges the bypass, noting that `getPerasCertInBlock` always returns `Nothing` and that the HFC plumbing for `BlockSupportsPeras` is not yet in place: [8](#0-7) 

---

### Impact Explanation

When Peras is enabled (e.g., in a private testnet or future mainnet deployment), an unprivileged peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the target node's VolatileDB.
2. Send it via the ObjectDiffusion mini-protocol.
3. The certificate passes "validation" unconditionally and is stored.
4. Chain selection is re-triggered for the boosted block; the attacker's chosen chain gains `perasWeight` additional weight.
5. If the boosted chain's total weight now exceeds the current selection's total weight, the node switches to the attacker's chain.

This is a **bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation** — matching the "Critical" impact tier: bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance.

---

### Likelihood Explanation

- The entry path is a standard network mini-protocol message; no special privileges, keys, or stake are required.
- The degenerate instance is the only instance in the codebase — there is no proper Cardano override.
- The code is wired into the production `ChainDB` path via `makePerasCertPoolWriterFromChainDB`.
- Exploitability is gated on Peras being enabled; the CHANGELOG notes it is disabled by default, but the code is present and the vulnerability is latent for any deployment that enables Peras (including private testnets, which are explicitly in scope).

---

### Recommendation

Replace the unconditional `Right` stub in `validatePerasCert` with actual cryptographic and structural validation before the Peras certificate diffusion protocol is enabled in any network. At minimum, gate the `processCerts` path so that certificates are only accepted when a proper, non-degenerate `BlockSupportsPeras` instance with real validation is in scope. The TODO at `cardano-peras/issues/120` tracks this work and must be resolved before Peras is activated.

---

### Proof of Concept

**Private-testnet sequence (Peras enabled):**

1. Node A is running with Peras enabled. Its VolatileDB contains block `B` on a minority fork.
2. Attacker (unprivileged peer) connects to Node A via the ObjectDiffusion protocol.
3. Attacker sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B) }` with a fabricated (invalid) aggregate BLS signature.
4. Node A calls `processCerts ... (validatePerasCert mkPerasParams) ...`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` without inspecting the signature.
6. The certificate is added to `PerasCertDB`; `addPerasCertAsync` is called.
7. `chainSelSync` triggers `chainSelectionForBlock` for block `B`.
8. `getPerasWeightSnapshot` now includes `point(B) → perasWeight`; `weightBoostOfFragment` returns a non-zero boost for any fragment containing `B`.
9. `preferAnchoredCandidate` compares `wsvTotalWeight` of the current chain against the candidate containing `B`; if the boost tips the balance, Node A switches to the minority fork. [1](#0-0) [9](#0-8) [10](#0-9) [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-105)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
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
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L63-68)
```haskell
instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L75-82)
```haskell
mkPerasWeightSnapshot ::
  StandardHash blk =>
  [(Point blk, PerasWeight)] ->
  PerasWeightSnapshot blk
mkPerasWeightSnapshot =
  Foldable.foldl'
    (\s (pt, weight) -> addToPerasWeightSnapshot pt weight s)
    emptyPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/unstable-consensus-testlib/Test/Ouroboros/Storage/TestBlock.hs (L626-632)
```haskell
                  -- NOTE: this bypasses the degenerate global implementation of
                  -- 'BlockSupportsPeras.getPerasCertInBlock' for 'TestBlock',
                  -- which currently always returns 'Nothing'.
                  --
                  -- TODO: refactor this to use 'getPerasCertInBlock' after the
                  -- HFC plumbing for 'BlockSupportsPeras' is in place.
                  certRoundInBlock = tbPerasCertRound testBody
```
