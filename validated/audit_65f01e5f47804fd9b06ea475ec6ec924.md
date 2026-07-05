### Title
Unconditional Certificate Acceptance in `validatePerasCert` Enables Unauthorized Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the node accepts it as "validated," stores it in the `PerasCertDB`, and immediately triggers chain selection for the attacker-chosen block. This is a direct analog of the original report's pattern: a required authorization/ownership check is entirely absent, so an external caller can manipulate state they do not own.

---

### Finding Description

**Root cause — the missing check**

In the `BlockSupportsPeras` instance (the universal degenerate instance used for all block types), `validatePerasCert` is:

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

No quorum check, no aggregate BLS signature verification, no voter eligibility check, no round-number plausibility check — the function wraps the raw peer-supplied `PerasCert` directly into a `ValidatedPerasCert` and returns `Right`. The `PerasValidationErr` type is a single opaque constructor with no variants, making it structurally impossible to express any rejection reason. [2](#0-1) 

**Structural parallel to the original bug**

In the original report, skipping the `exit` boolean left `tOLPId = 0`, and the subsequent `unlock` operation used the attacker-supplied `tokenId` without an ownership check. Here, the entire validation body is skipped (replaced by an unconditional `Right`), so the attacker-supplied `pcCertBoostedBlock` is used in chain selection without any proof that a legitimate quorum of stake pools actually voted for it.

**Inbound path — how a peer reaches this code**

`makePerasVotePoolWriterFromChainDB` (and the cert-specific writer) wire `validatePerasCert mkPerasParams` as the validation callback passed to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
(void . ChainDB.addPerasCertAsync chainDB)
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound cert; if all pass (they always do), each is timestamped and forwarded to `addPerasCertAsync`: [4](#0-3) 

`addPerasCertAsync` enqueues the cert for `chainSelSync`, which adds it to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

The `PerasWeightSnapshot` built from stored certs is then used in chain selection to add `vpcCertBoost` weight to the attacker-chosen block: [6](#0-5) 

**Secondary issue — `validatePerasVote` also skips signature verification**

`validatePerasVote` only checks that the `pvVoteVoterId` exists in the stake distribution; it does not verify the vote's cryptographic signature. An attacker can forge votes for any registered pool ID. If enough forged votes accumulate to reach quorum, `updatePerasRoundVoteStates` automatically forges a certificate and injects it into chain selection via the same path above. [7](#0-6) 

---

### Impact Explanation

**Severity: High — chain selection manipulation by an unprivileged peer.**

A single malicious peer can send a `PerasCert` naming any block in the VolatileDB as the boosted target. The node will:
1. Accept the cert as validated (no rejection possible).
2. Store it in `PerasCertDB`, updating the `PerasWeightSnapshot`.
3. Trigger `chainSelectionForBlock` for the attacker-chosen block, potentially switching the node's preferred chain to a fork the attacker controls.

This directly matches the allowed impact category: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

The Peras boost weight (`perasWeight params`) is added unconditionally to the attacker-chosen block, which can tip chain selection in favor of a minority fork, causing the honest node to diverge from the canonical chain.

---

### Likelihood Explanation

**High.** The attack requires only a network connection to the target node's Peras object-diffusion mini-protocol endpoint. No keys, no stake, no prior interaction are needed. The `PerasCert` type is serializable and its fields (`pcCertRound`, `pcCertBoostedBlock`) are fully attacker-controlled. The validation function has no conditional branches — it cannot reject any input.

---

### Recommendation

Replace the stub implementation with real validation before the Peras protocol is activated on any network. At minimum:

1. **`validatePerasCert`**: Verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregated public keys of the claimed voters, check that the claimed voters form a quorum of stake, and verify each voter's eligibility proof. The concrete `PerasCert` type in `Peras/Cert/V1.hs` already carries `pcSignature :: AggregateVoteSignature PerasBLSCrypto` and `pcVoters :: PerasCertVoters` — these must be checked. [8](#0-7) 

2. **`validatePerasVote`**: Add cryptographic signature verification (using `verifyVoteSignature`) in addition to the existing stake-distribution lookup, analogous to `implVerifyVote` in `EveryoneVotes.hs`. [9](#0-8) 

3. Enrich `PerasValidationErr` with concrete error variants so that rejection reasons are distinguishable and auditable.

---

### Proof of Concept

**Attacker-controlled entry path (no privileges required):**

```
Attacker peer
  │
  │  sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <fork tip hash> }
  │  via Peras object-diffusion mini-protocol
  ▼
processCerts  [PerasCert.hs:164]
  │  calls validatePerasCert mkPerasParams cert
  │  → always returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = W })
  ▼
ChainDB.addPerasCertAsync  [ChainSel.hs:303]
  ▼
chainSelSync / ChainSelAddPerasCert  [ChainSel.hs:483]
  │  adds cert to PerasCertDB
  │  PerasWeightSnapshot now gives block <fork tip hash> extra weight W
  │  calls chainSelectionForBlock for <fork tip hash>
  ▼
Node switches preferred chain to attacker-chosen fork
```

The attacker needs only to know a valid block hash present in the target node's VolatileDB (obtainable via the ChainSync mini-protocol) and the current Peras round number (derivable from the current slot). No cryptographic material is required because `validatePerasCert` performs no signature check. [1](#0-0) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```
