### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production code path for processing inbound Peras certificates from peers uses a stub implementation of `validatePerasCert` that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or semantic checks. Any unprivileged peer can therefore submit a crafted `PerasCert` for any round number and any block point, have it accepted without rejection, and cause the receiving node to re-run chain selection with an artificially boosted weight for an attacker-chosen block — potentially forcing the node to switch to a non-canonical fork.

---

### Finding Description

**Vulnerable function — always-succeeding stub:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase — a catch-all `instance StandardHash blk => BlockSupportsPeras blk` explicitly labelled a "degenerate instance for all blks to get things to compile." [2](#0-1) 

**Production inbound path — both writers call the stub:**

`makePerasCertPoolWriterFromChainDB` (the function explicitly documented as "for actual production use") passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [3](#0-2) 

`processCerts` calls the validator on every inbound certificate and, if validation succeeds (which it always does), timestamps the certificate and forwards it to `addPerasCertAsync`: [4](#0-3) 

**Chain-selection consequence:**

`chainSelSync` processes the queued certificate. It adds it to the `PerasCertDB`, reads the boosted block from the `VolatileDB`, and unconditionally triggers `chainSelectionForBlock` for that block: [5](#0-4) 

The `PerasWeightSnapshot` used during chain comparison is built directly from the accepted certificates: [6](#0-5) 

Chain selection then compares total weight (`blockNo + weightBoost`) and switches to the heavier fragment: [7](#0-6) 

The default `perasWeight` is **15**, meaning a single forged certificate can make a fork appear 15 blocks heavier than it actually is: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can submit a `PerasCert` that:
1. Claims any `PerasRoundNo` (no round-currency check),
2. Claims any `Point blk` as the boosted block (no block-existence or chain-membership check),
3. Carries no BLS aggregate signature or committee-eligibility proof (none are verified).

The certificate is accepted, stored, and used to re-run chain selection. If the attacker's chosen block is on a fork that is currently shorter than the honest chain by fewer than `perasWeight` (15) blocks, the node will switch to that fork. Multiple forged certificates for the same fork compound the effect additively (`addToPerasWeightSnapshot` sums weights per point).

This directly enables:
- **Unauthorized chain-weight manipulation**: a node is made to prefer a non-canonical chain without the attacker controlling any stake.
- **Bypass of Peras certificate validation**: the entire BLS aggregate-signature and committee-sortition check is absent.

---

### Likelihood Explanation

The Object Diffusion mini-protocol for Peras certificates is reachable by any connected peer. No stake, no key material, and no prior chain knowledge beyond a target block hash (obtainable from the public chain) is required. The attacker only needs to craft a `PerasCert` with the desired `pcCertRound` and `pcCertBoostedBlock` fields and send it over the wire. The `processCerts` function will accept it, timestamp it, and enqueue it for chain selection immediately.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The BLS aggregate signature over `(roundNo, boostedBlockHash)` against the declared committee members' public keys.
2. Each voter's committee-eligibility proof (VRF sortition) for the claimed round.
3. That the total stake of the signers meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. That the boosted block's slot satisfies the `perasBlockMinSlots` age requirement relative to the round start.

Until a real implementation is available, the node should not accept externally supplied `PerasCert` objects (i.e., the Object Diffusion writer for certificates should be disabled or gated behind a feature flag that is off by default).

---

### Proof of Concept

The complete attack path in pseudocode:

```
1. Attacker connects to victim node via the Object Diffusion mini-protocol.

2. Attacker observes a fork block B_fork at slot S, currently 10 blocks
   shorter than the honest tip (weight deficit = 10 < perasWeight = 15).

3. Attacker crafts:
     cert = PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = Point S hash(B_fork) }
   No BLS signature, no eligibility proof — the struct is trivially serialisable.

4. Attacker sends [cert] to the victim via the ObjectDiffusion protocol.

5. processCerts calls validatePerasCert mkPerasParams cert
   => always returns Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })

6. addPerasCertAsync enqueues ChainSelAddPerasCert.

7. chainSelSync:
   - Adds cert to PerasCertDB (weight snapshot now has +15 for B_fork's point).
   - Calls chainSelectionForBlock for B_fork.

8. Chain selection compares:
     honest chain total weight  = blockNo_honest + 0   (no boosts)
     fork    chain total weight = blockNo_fork   + 15

   Since blockNo_fork + 15 > blockNo_honest (10 < 15), the node switches to the fork.

9. Victim node now follows the attacker-chosen non-canonical chain.
``` [1](#0-0) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
