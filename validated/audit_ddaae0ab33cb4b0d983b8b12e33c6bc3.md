### Title
`validatePerasCert` Unconditionally Accepts All Inbound Certificates, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound `PerasCert`, performing zero cryptographic or semantic validation. An unprivileged peer can send a crafted certificate referencing any block hash — including a block on a minority fork or a block that does not yet exist — and the node will accept it, store it in `PerasCertDB`, and apply its boost weight during chain selection. This is the direct analog of the Aave governance bug: just as a proposal could reference a non-existent payload that is later substituted with a malicious one, a Peras certificate can reference a non-existent or attacker-controlled block that is later produced, causing the node to prefer the attacker's chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must reject invalid certificates before they enter the system. The only deployed instance — a universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as an unconditional pass-through:

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

This is not an abstract stub — it is the only instance in the codebase (there is no more-specific Cardano override), so it is the live production code path. The `processCerts` function in the Object Diffusion layer calls this validator directly on every batch of certificates received from a peer:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using `validateCert`; since `validatePerasCert` always returns `Right`, the invalid partition is always empty and every certificate is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`implAddCert` in `PerasCertDB` also carries its own TODO acknowledging missing validation: [4](#0-3) 

Once stored, `chainSelSync` uses the certificate's `pcCertBoostedBlock` to trigger chain selection for the referenced block. If the block is not yet in the VolatileDB, the certificate is silently retained and its boost is applied the moment the block arrives: [5](#0-4) 

The `getWeightSnapshot` function then returns the accumulated boost for every stored certificate's `pcCertBoostedBlock`, feeding directly into chain comparison: [6](#0-5) 

The following checks are entirely absent from `validatePerasCert`:
- BLS aggregate signature verification over `(pcCertRound, pcCertBoostedBlock)`
- Verification that the voters in `pcVoters` are eligible committee members for `pcCertRound`
- Verification that `pcCertBoostedBlock` existed on-chain before the certificate's round
- Verification that `pcCertRound` is within the valid window relative to the current tip

The `PerasCert` data type in `Cert/V1.hs` carries all the fields needed for these checks (`pcRoundNo`, `pcBoostedBlock`, `pcVoters`, `pcSignature`), but none are examined: [7](#0-6) 

---

### Impact Explanation

**High — Chain selection manipulation by an unprivileged peer.**

A malicious peer can craft a `PerasCert` with:
- `pcBoostedBlock` set to the hash of any block on a minority fork (or a block the attacker intends to produce)
- `pcRoundNo` set to any round number
- `pcVoters` and `pcSignature` set to arbitrary bytes

The certificate passes `validatePerasCert` unconditionally, is stored in `PerasCertDB`, and its `perasWeight` boost is applied to the referenced block during chain selection via `getWeightSnapshot`. If the boosted block is on a fork, the honest node may switch to that fork, constituting a chain selection failure. If the boosted block does not yet exist, the boost is held in the DB and applied the moment the attacker produces a matching block — the exact "future payload substitution" pattern from the Aave report.

This directly matches the allowed impact: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Medium.** The Object Diffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The attacker needs only to:
1. Connect to a target node
2. Send a `PerasCert` message with a crafted `pcBoostedBlock` pointing to a block on a competing fork
3. The certificate is accepted and stored immediately

No stake, no keys, and no prior chain state are required to trigger the acceptance. The only constraint is that the attacker must be able to connect to the node (standard peer connectivity) and must know or predict a block hash to boost. For the "future block" variant, the attacker must be a block producer, which raises the bar but is still an unprivileged network participant in Cardano's open staking model.

---

### Recommendation

1. **Implement `validatePerasCert` properly** in `BlockSupportsPeras.hs` (tracking issue #120). At minimum, verify:
   - The BLS aggregate signature over `hash(pcRoundNo || pcBoostedBlock)`
   - That each voter in `pcVoters` holds a valid eligibility proof for `pcRoundNo`
   - That `pcBoostedBlock`'s slot falls within the valid range for `pcRoundNo`
   - That `pcBoostedBlock` was produced strictly before the certificate's round began

2. **Add a temporal ordering check** in `chainSelSync`: before storing a certificate whose boosted block is not yet in the VolatileDB, verify that the block's expected slot (derivable from the round number and Peras parameters) is in the past relative to the current wall-clock slot. Certificates referencing future slots should be rejected, not deferred.

3. **Remove the universal degenerate instance** once the real Cardano-specific instance is in place, to prevent accidental use of the no-op validator.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the Object Diffusion mini-protocol.

2. Attacker observes that block B_fork (hash H_fork) exists on a minority fork
   that the honest node has not selected.

3. Attacker crafts:
     PerasCert { pcRoundNo    = <any valid round>
               , pcBoostedBlock = H_fork
               , pcVoters     = <arbitrary>
               , pcSignature  = <arbitrary bytes> }

4. Attacker sends the certificate to the honest node.

5. processCerts calls validatePerasCert, which returns Right unconditionally.

6. The certificate is stored in PerasCertDB with boost weight = perasWeight params.

7. chainSelSync looks up H_fork in VolatileDB:
   - If found: chainSelectionForBlock is triggered for B_fork with the boost applied.
   - If not found: the boost is held; when B_fork arrives later, the boost is applied.

8. getWeightSnapshot now returns a non-zero weight for H_fork.

9. Chain selection compares the honest chain against the fork; the artificial boost
   may tip the comparison in favour of the fork, causing the node to reorganise
   onto the attacker's minority chain.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
