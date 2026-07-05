### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance for all block types contains a stub `validatePerasCert` implementation that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural validation. Because this stub is the active implementation wired into the Peras certificate object-diffusion inbound path, any unprivileged peer can send a crafted `PerasCert` that names an arbitrary block as the boosted target. The certificate passes validation, is stored in `PerasCertDB`, and triggers `chainSelectionForBlock` for the attacker-chosen block, applying a Peras weight boost that can cause the honest node to switch to a non-canonical chain.

---

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

This is the universal instance (`instance StandardHash blk => BlockSupportsPeras blk`) that applies to all block types until a more specific instance is provided. The comment at line 318 confirms it is a placeholder: [2](#0-1) 

**Inbound path — `processCerts` calls this stub directly:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the validation function for all inbound peer-supplied certificates: [3](#0-2) 

`processCerts` then calls this function on every certificate not already in the DB, and if it returns `Right` (which it always does), the certificate is timestamped and forwarded to `addPerasCertAsync`: [4](#0-3) 

**State mutation — accepted cert triggers chain selection:**

`chainSelSync` processes the accepted `ValidatedPerasCert`. After adding it to `PerasCertDB`, it calls `chainSelectionForBlock` for the block named in `pcCertBoostedBlock`, applying the Peras weight boost: [5](#0-4) 

The `PerasCert` data type contains only `pcCertRound` and `pcCertBoostedBlock` — both fully attacker-controlled with no signature field: [6](#0-5) 

**Secondary stub — `validatePerasVote` also skips signature verification:**

The vote validation stub only checks stake-distribution membership (a plain map lookup) and never verifies a cryptographic vote signature. An attacker who knows any active voter ID can forge votes for that voter, accumulate fake quorum, and cause the node to internally forge a certificate: [7](#0-6) 

---

### Impact Explanation

**Classification: High — chain selection manipulation.**

An unprivileged peer can:

1. Send a valid (but non-preferred) fork block, which is stored in the node's `VolatileDB`.
2. Send a crafted `PerasCert` with `pcCertBoostedBlock` pointing to that fork block.
3. The cert passes `validatePerasCert` unconditionally.
4. `chainSelSync` applies the Peras weight boost (`perasWeight params`) to the fork block and triggers `chainSelectionForBlock`.
5. If the fork + boost exceeds the current chain's weight, the node switches to the attacker's fork.

This matches the allowed impact: *"chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The secondary vote-forgery path (via `validatePerasVote`) allows the same outcome without even needing to send a certificate directly — the node forges the certificate itself from the fake votes.

---

### Likelihood Explanation

**Medium-to-High.** The object-diffusion inbound handler is active and reachable from any connected peer. No privilege, key material, or stake is required. The attacker only needs to know a valid voter ID (publicly observable from the stake distribution) and the hash of a block already in the target node's `VolatileDB`. The stub is the only active implementation; there is no fallback check.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) implementations with real cryptographic validation before the Peras object-diffusion protocol is enabled on any network. At minimum, gate the inbound handlers so that they reject all certificates (return `Left` unconditionally) until the real validation logic referenced in issue #120 is in place. This mirrors the fix described in the external report: verify that the triggering condition (a legitimately signed certificate/vote) actually holds before performing any state mutation.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the Peras certificate object-diffusion mini-protocol.
2. Obtain the hash of any block `B` present in the node's `VolatileDB` but not on its current chain (e.g., by first diffusing a competing fork block).
3. Construct a `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B) }` for any round `r`.
4. Send the certificate to the node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert` unconditionally.
6. `chainSelSync` calls `chainSelectionForBlock` for `B` with the Peras weight boost applied.
7. If `weight(B's chain) + perasWeight params > weight(current chain)`, the node switches to `B`'s chain — a non-canonical fork chosen by the attacker. [1](#0-0) [4](#0-3) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
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
