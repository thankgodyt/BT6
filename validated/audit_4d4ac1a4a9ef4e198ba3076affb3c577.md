### Title
Peras Certificate Validation Bypass Allows Adversarial Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound certificate without performing any cryptographic or structural checks. An unprivileged peer can send a crafted `PerasCert` for any block, have it accepted as valid, stored in the `PerasCertDB`, and used to boost that block's weight in chain selection — causing an honest node to prefer an adversarial fork over the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a certificate before it enters the node's state. The universal instance (the only one that exists, used for all block types) implements this gate as a no-op:

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

Every certificate, regardless of content, is returned as `Right` (valid) with a full `PerasWeight 15` boost attached. [1](#0-0) 

This function is the sole validator called in `processCerts`, the inbound handler for certificates received from remote peers via the ObjectDiffusion mini-protocol. Both production pool writers — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — invoke it with the hardcoded `mkPerasParams`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` passes every non-duplicate certificate through `validateCert`, and if all pass (they always do), adds them to the database: [4](#0-3) 

Once stored, a certificate triggers `chainSelSync` → `chainSelectionForBlock`, which re-runs chain selection accounting for the new boost: [5](#0-4) 

Chain selection uses `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`. A fraudulent certificate adds `PerasWeight 15` to any block the attacker names: [6](#0-5) 

The missing checks that `validatePerasCert` should perform include, at minimum:
- Aggregate BLS signature verification over the claimed quorum of votes
- Verification that the claimed voters were eligible committee members for the stated round
- Verification that the boosted block existed and was old enough (`perasBlockMinSlots`)
- Verification that the certificate's round number is within the valid window (`perasCertMaxRounds`)

None of these are performed. The analogous `validatePerasVote` also omits cryptographic signature verification, only checking stake-distribution membership: [7](#0-6) 

---

### Impact Explanation

An adversary controlling a single peer connection can send a `PerasCert` naming any block hash as the boosted block. The certificate is accepted unconditionally, stored, and causes the node to re-run chain selection with that block receiving `PerasWeight 15` additional weight. Since `wsvTotalWeight` is the primary comparator in `preferCandidate`, a chain containing the adversarially boosted block will be preferred over an honest chain of equal or slightly greater block-number length. This constitutes an unauthorized chain-selection manipulation: the node adopts a non-canonical fork driven purely by a crafted network message, bypassing all Peras certificate authorization.

This matches the **High** impact category: *Bypass of certificate/vote verification checks that enables unauthorized certificate acceptance*, and *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain*.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a production code path reachable by any connected peer. No stake, key material, or privileged access is required — only a TCP connection. The attacker needs only to construct a `PerasCert` CBOR value with a chosen `pcCertRound` and `pcCertBoostedBlock`, which is trivially serializable from the public `Serialise` instance: [8](#0-7) 

The TODO comments and the linked issue (`cardano-peras/issues/120`) confirm the developers are aware validation is absent, but the code is wired into the production `ChainDB` path today.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs the full set of checks required by the Peras protocol specification before returning `Right`:

1. **Quorum membership**: verify each claimed voter's seat index is within the committee bounds and that the voter is eligible for the stated round.
2. **Aggregate signature**: verify the BLS aggregate signature over `(electionId, candidate)` using the aggregated verification keys of the claimed voters.
3. **Round validity**: verify `pcCertRound` falls within the acceptable window relative to the current chain tip.
4. **Block age**: verify the boosted block's slot satisfies `perasBlockMinSlots`.
5. **VRF outputs** (for non-persistent voters): batch-verify VRF outputs as done in `WFALS.implVerifyCert`.

Until the full implementation is ready, the `processCerts` inbound handler should reject all certificates rather than accept them unconditionally, to prevent the current bypass from being exploited on a Peras-enabled network.

---

### Proof of Concept

1. Connect to a node with Peras enabled via the ObjectDiffusion mini-protocol for certificates.
2. Craft a CBOR-encoded `PerasCert` with:
   - `pcCertRound`: any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock`: the `Point` of a block on a competing (adversarial) fork
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
5. The certificate is stored in `PerasCertDB` and `chainSelSync` triggers chain selection for the boosted block.
6. `weightBoostOfFragment` now adds `PerasWeight 15` to any fragment containing the adversarially named block.
7. `preferCandidate` via `WeightedSelectView.preferCandidate` compares `wsvTotalWeight` and switches to the adversarial chain if its boosted total weight exceeds the honest chain's block-number-only weight. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
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
