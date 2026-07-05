### Title
`validatePerasCert` Unconditionally Accepts Any Peras Certificate, Enabling Forged-Certificate Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can therefore send a crafted `PerasCert` naming any block as the boosted target, have it accepted as "validated," and cause the receiving node to re-run chain selection with an artificially inflated weight for that block — potentially switching to a non-canonical fork.

---

### Finding Description

`SupportsPeras.hs` defines a catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` that is explicitly marked as a temporary placeholder (TODO, issue #120). Its `validatePerasCert` body is:

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

Because this is a universal instance (`StandardHash blk =>`), it is the instance resolved for every concrete block type in the codebase. No override with real validation exists.

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes exactly this stub as the validator:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls `validateCert` on every received certificate and, because the stub always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`chainSelSync` then stores the certificate in `PerasCertDB` and immediately triggers `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection uses `wsvTotalWeight`, which adds the certificate's `PerasWeight` boost directly to the block number when comparing candidate chains:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

`preferCandidate` then switches to the candidate chain if its `wsvTotalWeight` exceeds the current chain's: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock` and any `PerasRoundNo`. Because `validatePerasCert` never rejects it, the certificate is stored and the boosted block's chain fragment gains `perasWeight` (a configurable `Word64`) added to its effective block-number weight. If the forged boost is large enough, the node switches to the attacker's fork, constituting a **chain selection safety failure**: an honest node accepts a non-canonical chain driven entirely by a forged, unauthenticated certificate from an unprivileged peer.

The analog to the external report is direct: just as any user could transfer tokens to the `TOTAL_GOVERNANCE_SCORE` address to inflate the quorum denominator and stall governance, any peer here can inject a forged certificate to inflate a fork's weight and override honest chain selection.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is reachable by any connected peer — no stake, no key material, no special role is required. The crafted certificate needs only a valid CBOR encoding of `PerasCert` (two fields: `PerasRoundNo` and a `Point blk`). The `processCerts` deduplication check only filters certificates whose `PerasRoundNo` is already in the DB, so an attacker can use any fresh round number. The attack is therefore trivially executable by any peer on the network.

---

### Recommendation

1. **Implement real `validatePerasCert`** before enabling the Peras certificate diffusion path in any environment where untrusted peers can connect. At minimum, the certificate must be checked against the committee selection output for the claimed round: the aggregate BLS signature must verify against the aggregate public key of the declared voters, and the claimed boosted block must be a known, valid block within the allowed age window.

2. **Gate the diffusion path** behind a feature flag or era check so that the stub instance cannot be reached from the network until real validation is wired in.

3. **Add a compile-time or runtime guard** (e.g., `error "validatePerasCert: not yet implemented"`) to the stub so that any accidental production use fails loudly rather than silently accepting all certificates.

---

### Proof of Concept

```
Attacker (any peer)
  │
  │  sends PerasCert { pcCertRound = freshRound
  │                  , pcCertBoostedBlock = pointOfForkBlock }
  │  via Peras certificate diffusion mini-protocol
  ▼
makePerasCertPoolWriterFromChainDB
  └─ processCerts ... (validatePerasCert mkPerasParams) ...
       │
       │  validatePerasCert always returns Right ValidatedPerasCert
       │  { vpcCertBoost = perasWeight params }   ← no checks performed
       ▼
  ChainDB.addPerasCertAsync cert
       ▼
  chainSelSync (ChainSelAddPerasCert cert)
       │  stores cert in PerasCertDB
       │  calls chainSelectionForBlock for forkBlock
       ▼
  weightedSelectView computes
       wsvTotalWeight(fork) = blockNo(fork) + perasWeight   ← artificially inflated
       wsvTotalWeight(honest) = blockNo(honest)
       if wsvTotalWeight(fork) > wsvTotalWeight(honest):
           node switches to fork  ← chain selection safety failure
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
