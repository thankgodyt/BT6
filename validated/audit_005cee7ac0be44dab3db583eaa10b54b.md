### Title
Unconditional `validatePerasCert` Acceptance Enables Unauthorized Peras Chain-Selection Manipulation via Crafted Certificate — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or structural validation. An unprivileged peer can submit a crafted `PerasCert` that claims to boost any block in the VolatileDB. Because the certificate passes "validation" without any check, it is stored in the `PerasCertDB` and immediately triggers chain selection for the boosted block, potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the gate that must authenticate inbound Peras certificates before they can influence chain selection. The degenerate instance that covers all block types in production is:

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

This function ignores `params` and `cert` entirely and always returns a `ValidatedPerasCert` carrying the full configured `perasWeight` boost. No quorum check, no committee membership check, no cryptographic signature verification, and no round/block validity check is performed.

The production inbound path for peer-submitted certificates is `makePerasCertPoolWriterFromChainDB`, which wires this stub directly into the live ChainDB:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then calls `validateCert` on every certificate not already in the DB, and on success passes it to `addCert` / `addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which processes it as `ChainSelAddPerasCert`: [4](#0-3) 

If the boosted block is present in the VolatileDB, `chainSelectionForBlock` is called unconditionally for that block. Chain selection then uses `WeightedSelectView`, where `wsvTotalWeight` adds the certificate's `wsvWeightBoost` to the block number: [5](#0-4) 

A fork whose tip block carries a fraudulent boost can therefore appear heavier than the honest chain, causing the node to switch.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash present in the target node's VolatileDB. Because `validatePerasCert` always succeeds, the certificate is stored and chain selection is triggered for the named block. If that block is on a minority fork, the node's `WeightedSelectView` comparison will now favour that fork (its total weight = block number + fraudulent boost), causing the node to roll back its current chain and adopt the attacker-chosen fork. This is a **chain-selection error** that lets an unprivileged peer make an honest node prefer a non-canonical chain, violating the Peras security assumption that only legitimately quorum-certified blocks receive a boost.

---

### Likelihood Explanation

The Peras certificate diffusion miniprotocol is reachable by any connected peer without authentication. The attacker only needs to know (or guess) a block hash present in the target's VolatileDB — information that is routinely exchanged during normal ChainSync. The crafted certificate requires no cryptographic material whatsoever because `validatePerasCert` ignores the certificate content entirely. The attack is therefore trivially executable by any peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The certificate carries a valid aggregate signature from a quorum of committee members for the claimed round and block.
2. The signers are legitimate committee members for that round (per the stake distribution / committee selection context).
3. The round number is within the acceptable window relative to the current chain tip.

Until the real implementation is in place, inbound certificates from untrusted peers should be rejected entirely (return `Left PerasValidationErr` unconditionally) rather than accepted unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node as a normal peer via the Peras object-diffusion miniprotocol.
2. Attacker learns block hash `H` of a block on a minority fork present in the target's VolatileDB (obtained via normal ChainSync header exchange).
3. Attacker sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint slot H }` to the target.
4. `processCerts` filters out already-known rounds, then calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` — no validation performed. [6](#0-5) 
6. The certificate is timestamped and passed to `addPerasCertAsync`, which enqueues `ChainSelAddPerasCert`.
7. `chainSelSync` finds block `H` in the VolatileDB and calls `chainSelectionForBlock` for it. [7](#0-6) 
8. Chain selection computes `wsvTotalWeight` for the fork containing `H`; the fraudulent boost makes it heavier than the honest chain.
9. The node rolls back its current selection and adopts the attacker-chosen fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
