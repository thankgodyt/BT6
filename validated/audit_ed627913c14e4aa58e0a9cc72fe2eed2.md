### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Any unprivileged peer can send an arbitrarily crafted `PerasCert` that will be accepted, stored, and used to trigger chain selection for the boosted block, bypassing the Peras certificate-validation gate entirely.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` instance for all `StandardHash blk` blocks implements `validatePerasCert` as:

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

This function is the sole validation gate for inbound Peras certificates. It is called by `processCerts` in the object-diffusion inbound path:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted and timestamped as valid.

The accepted certificate is then forwarded to `addPerasCertAsync`, which calls `chainSelSync` → `chainSelectionForBlock`, potentially switching the node's preferred chain to one boosted by the attacker-supplied certificate: [3](#0-2) 

The analogous gap exists in `validatePerasVote` (also marked TODO for full validation), but `validatePerasCert` is the more critical path because a certificate directly boosts chain weight.

Additionally, `PerasParams` — the parameter bundle consumed by both validation stubs — carries documented inter-parameter invariants that are never enforced at construction time. The comment in `mkPerasParams` states `perasCertArrivalThreshold` "must be strictly smaller than `perasRoundLength`", and `perasBlockMinSlots` "must be between 30 and 900", yet `PerasParams` is a plain record with no validation: [4](#0-3) [5](#0-4) 

The `sanityCheckConfig` function, which runs on startup, only checks `checkSecurityParamConsistency` and does not validate any Peras parameter constraints: [6](#0-5) 

---

### Impact Explanation

When the Peras feature flag is enabled (`rnFeatureFlags`), an unprivileged peer connected via the object-diffusion mini-protocol can:

1. Forge a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block in the VolatileDB.
2. The stub `validatePerasCert` accepts it unconditionally.
3. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block, potentially causing the node to switch to a chain it would otherwise not prefer.
4. Because the certificate boost (`perasWeight`) is added to the chain's weight, a shorter adversarial chain can be made to appear heavier than the honest chain, causing the node to diverge from the canonical chain.

This is a **bypass of Peras certificate validation** enabling unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: Bypass of certificate/vote checks that enables unauthorized certificate acceptance" impact category.

---

### Likelihood Explanation

**Medium-to-High** when Peras is enabled. The object-diffusion mini-protocol for Peras certificates is wired into the node kernel when the Peras feature flag is set. No special privileges, keys, or stake are required — any connected peer can send a `PerasCert` CBOR message. The stub has been present since the Peras integration was merged and is explicitly tracked as an open issue (`cardano-peras#120`), meaning it has not been addressed.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert`: verify the certificate's committee signatures, check that the boosted block hash is known and valid, and confirm the round number is within the expected window.
2. **Implement real validation** in `validatePerasVote`: verify the voter's VRF/KES credentials and that the vote signature is correct.
3. **Add inter-parameter constraint checks** to `PerasParams` construction (or to `sanityCheckConfig`) enforcing `perasCertArrivalThreshold < perasRoundLength`, `30 ≤ perasBlockMinSlots ≤ 900`, and `perasIgnoranceRounds == perasCertMaxRounds`.
4. Until (1) and (2) are complete, gate the object-diffusion certificate/vote inbound handlers behind the Peras feature flag so that nodes with Peras disabled cannot be targeted.

---

### Proof of Concept

With Peras enabled on a private testnet:

```
# Attacker node connects to honest node via NTN
# Crafts a PerasCert CBOR payload:
#   pcCertRound  = <current_round>
#   pcCertBoostedBlock = <hash of block on attacker's shorter fork>
# Sends it via the ObjectDiffusion mini-protocol

# processCerts calls validatePerasCert mkPerasParams cert
# => always returns Right (ValidatedPerasCert { vpcCertBoost = 15 })
# => cert is stored and addPerasCertAsync is called
# => chainSelSync triggers chainSelectionForBlock for the boosted block
# => honest node's chain weight for attacker's fork increases by perasWeight (15)
# => if attacker's fork length + 15 > honest chain length, node switches forks
```

The stub at line 353–358 of `SupportsPeras.hs` is the single necessary and sufficient vulnerable step; no other code path can reject the certificate before it reaches chain selection. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-390)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-132)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L147-151)
```haskell
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsSanityCheck.hs (L168-174)
```haskell
-- | Run all supported sanity checks on a given 'TopLevelConfig'.
sanityCheckConfig ::
  BlockSupportsSanityCheck blk =>
  TopLevelConfig blk ->
  [SanityCheckIssue]
sanityCheckConfig cfg =
  catMaybes [checkSecurityParamConsistency cfg]
```
