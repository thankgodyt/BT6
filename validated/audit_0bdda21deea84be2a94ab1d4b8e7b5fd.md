### Title
Unconditional `validatePerasCert` / Signature-Free `validatePerasVote` Bypass Enables Unauthorized Certificate Acceptance and Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships two stub validation functions that perform no meaningful cryptographic or protocol-level checks. `validatePerasCert` unconditionally returns `Right` for every inbound certificate, and `validatePerasVote` accepts any vote whose voter ID appears in the public stake-distribution map without verifying the vote signature or VRF eligibility proof. Both stubs are wired directly into the live inbound-object-diffusion handlers. An unprivileged peer can therefore inject arbitrary Peras certificates or forge votes for any known voter ID, causing the local node to accept them, update its VoteDB/CertDB, and potentially trigger chain selection for an attacker-chosen block.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:**

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

Every `PerasCert` received from any peer is immediately wrapped in `ValidatedPerasCert` and returned as `Right`, regardless of round number, boosted-block identity, aggregate signature, or quorum proof. No field of the certificate is inspected.

**Root cause — `validatePerasVote` skips all cryptographic checks:**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

The only check performed is a `Map.lookup` of the voter ID in the stake distribution. Vote signature, VRF eligibility proof, round-number validity, and block-point validity are all ignored. The stake distribution is public; any peer knows every valid voter ID.

**Inbound certificate path — `processCerts`:**

`processCerts` calls `validateCert` on each inbound certificate and, if all pass, adds them via `addPerasCertAsync`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken. [3](#0-2) 

**Inbound vote path — `processVotes`:**

`processVotes` validates each vote in a single STM transaction and, if all pass, adds them via `addVote`. Because `validatePerasVote` only checks voter-ID membership, any vote whose voter ID is in the stake distribution passes. [4](#0-3) 

**Chain-selection trigger — `chainSelSync` for `ChainSelAddPerasCert`:**

Once a certificate clears the "too old" guard, it is added to `cdbPerasCertDB` and `chainSelectionForBlock` is called for the boosted block. If that block is already in the VolatileDB, the node may switch to a chain containing it. [5](#0-4) 

**The degenerate instance is the only production instance:**

The comment acknowledges this is a placeholder, but it is the sole `BlockSupportsPeras` instance and is used in all production code paths. [6](#0-5) 

---

### Impact Explanation

**Bypass of certificate verification (Critical):** An unprivileged peer can craft a `PerasCert` naming any block at any round. `validatePerasCert` returns `Right` unconditionally. The certificate is stored in the CertDB and, if the boosted block is present in the VolatileDB, `chainSelectionForBlock` is invoked. This can cause the node to prefer a chain it would otherwise reject, constituting an unauthorized chain-selection manipulation.

**Bypass of vote verification (Critical):** An unprivileged peer can forge `PerasVote` messages for any voter ID present in the public stake distribution, targeting any block. Because no signature is checked, the votes are accepted, accumulate stake in the VoteDB, and can manufacture a quorum. The resulting certificate is then forwarded to `addPerasCertAsync`, triggering chain selection for the attacker-chosen block.

Both paths map directly to the ONCH-6 vulnerability class: just as `pop(call(...))` discarded the EVM return code and allowed state to be updated despite a failed external call, `validatePerasCert` discards all validation logic and always signals success, allowing any certificate to update consensus state regardless of its legitimacy.

---

### Likelihood Explanation

The object-diffusion miniprotocol is reachable by any peer that can establish a connection to the node. The stake distribution (voter IDs and their weights) is public on-chain data. No privileged access, key compromise, or stake majority is required. The attacker only needs to know a valid voter ID and the current round number, both of which are observable from the chain. The attack is therefore trivially executable by any connected peer.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate signature over `(round, boostedBlock)` against the committee's aggregate verification key, and confirm the certificate represents a genuine quorum.
2. **Implement real vote validation** in `validatePerasVote`: verify the individual vote signature and, for non-persistent committee members, the VRF eligibility proof, before accepting the vote into the VoteDB.
3. Until real validation is implemented, **gate the Peras object-diffusion handlers** so they are only active on private testnets, or add an explicit runtime guard that rejects all inbound Peras objects when the stub instance is in use.
4. Consider promoting `PerasVoteDbError` variants `MultipleWinnersInRound` and `ForgingCertError` from `ourBug` (`ShutdownPeer`) to `shutdownNode` in `consensusRethrowPolicy`, as the existing TODO comment acknowledges. [7](#0-6) 

---

### Proof of Concept

**Certificate injection (single message, no stake required):**

1. Connect to a target node via the object-diffusion miniprotocol.
2. Craft a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <hash of a block already in the peer's VolatileDB>`.
3. Send the certificate. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The certificate is stored in `cdbPerasCertDB` and `chainSelectionForBlock` is triggered for the boosted block.
5. The node's chain selection now treats that block as having additional Peras weight, potentially switching to a fork the attacker controls.

**Vote-based quorum forgery (requires knowing voter IDs from the stake distribution):**

1. Obtain the current `PerasVoteStakeDistr` (public on-chain data).
2. For each voter ID `v_i` with stake `s_i`, craft a `PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = v_i }` where `B` is the attacker's target block.
3. Send enough forged votes to exceed the quorum threshold. `validatePerasVote` accepts each one because `lookupPerasVoteStake` finds `v_i` in the distribution.
4. `implAddVote` accumulates stake; once `stakeAboveThreshold` is satisfied, `AddedPerasVoteAndGeneratedNewCert cert` is returned.
5. `addPerasVoteWithAsyncCertHandling` calls `addPerasCertAsync` with the forged certificate, triggering chain selection for block `B`. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-180)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/RethrowPolicy.hs (L103-108)
```haskell
    <> mkRethrowPolicy
      ( \_ctx (e :: PerasVoteDbError blk) ->
          case e of
            MultipleWinnersInRound{} -> ourBug -- TODO: should we instead shutdown the node?
            ForgingCertError{} -> ourBug
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
