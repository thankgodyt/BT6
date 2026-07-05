### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or protocol-level checks. Because this is the only instance in the codebase and is wired directly into the live Peras certificate mini-protocol inbound path, any unprivileged peer can send a crafted `PerasCert` message that will be accepted, stored, and used to apply a configurable weight boost to an arbitrary block during chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate that must verify a Peras certificate before it is stored and acted upon:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole concrete instance — a universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this as:

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

This always returns `Right`, regardless of the certificate's content. [1](#0-0) 

The network inbound path in `processCerts` calls this stub directly with the hardcoded `mkPerasParams` for every certificate received from a peer:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` partitions results into valid/invalid; since `validatePerasCert` never returns `Left`, every inbound certificate is classified as valid and forwarded to `addPerasCertAsync` on the `ChainDB`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to the `PerasCertDB` and triggers chain selection for the boosted block: [4](#0-3) 

The accepted certificate's boost is then incorporated into `PerasWeightSnapshot`, which is used by `weightedSelectView` to compute `wsvTotalWeight = blockNo + weightBoost` for chain comparison: [5](#0-4) 

The default `perasWeight` is 15 (equivalent to 15 blocks of chain length), set in `mkPerasParams`: [6](#0-5) 

A secondary, related gap exists in `validatePerasVote`: it only checks whether the voter ID appears in the stake distribution map, but performs no BLS signature verification or VRF eligibility proof check, allowing an attacker to impersonate any known voter and accumulate fake stake toward quorum: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send a single crafted `PerasCert` message claiming to boost any block point (including one on a minority fork). The node accepts it unconditionally, adds a weight of 15 to that block's chain fragment, and may switch its selection to a non-canonical chain. With the default `perasWeight = 15`, a fork only 15 blocks shorter than the honest chain becomes preferred. This constitutes:

- **Critical bypass of Peras certificate verification** enabling unauthorized certificate acceptance.
- **High chain-selection manipulation** allowing an unprivileged peer to make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate mini-protocol is wired into the live diffusion layer. Any peer that can establish a connection can send a `PerasCert` message. No stake, key material, or special privilege is required. The attack requires sending a single well-formed CBOR-encoded `PerasCert` (two fields: `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk`), which is trivially constructable.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's cryptographic proof of quorum (e.g., aggregate BLS signature over the claimed votes).
2. That the boosted block point is within the valid age window (`perasCertMaxRounds`).
3. That the certificate round number is consistent with the current chain state.

Until real validation is implemented, the inbound certificate path in `processCerts` / `makePerasCertPoolWriterFromChainDB` should reject all externally received certificates rather than accepting them unconditionally. The same applies to `validatePerasVote`, which must verify BLS signatures and VRF eligibility proofs before counting a vote's stake toward quorum.

---

### Proof of Concept

1. Attacker connects to a target node as a peer via the Peras certificate mini-protocol.
2. Attacker constructs a `PerasCert` with:
   - `pcCertRound = <any round number>`
   - `pcCertBoostedBlock = <point of a block on a minority fork>`
3. Attacker sends the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
4. The certificate is added to `PerasCertDB` via `addPerasCertAsync`.
5. `chainSelSync` triggers chain selection for the boosted block.
6. `weightedSelectView` computes `wsvTotalWeight = blockNo(fork_tip) + 15` for the minority fork.
7. If the honest chain's tip block number minus the fork's tip block number is ≤ 14, the node switches to the attacker's fork.
8. The attacker can repeat with a new `pcCertRound` to re-boost as needed (one certificate per round is stored; a new round number bypasses the duplicate check at `Set.member roundNo (pcdsCertIds pcds)`). [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
```
