### Title
Incomplete Peras Vote and Certificate Validation Allows Unauthorized Certificate Acceptance and Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` and `validatePerasCert` methods in the `BlockSupportsPeras` typeclass default implementation perform no cryptographic signature verification, no committee membership check, and no round eligibility check before accepting votes and certificates. An unprivileged peer can inject crafted votes or certificates via the Peras object-diffusion mini-protocol, bypass all meaningful validation, trigger unauthorized certificate forging, and cause honest nodes to boost an attacker-chosen block in chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `SupportsPeras.hs` defines the default production implementations of `validatePerasVote` and `validatePerasCert`. Both carry explicit TODO comments acknowledging that actual validation is absent:

`validatePerasVote` (lines 360–371) only performs a stake-distribution lookup. It does **not** verify:
- The cryptographic signature on the vote
- Whether the voter is an eligible committee member for the given round
- Whether the voted block is on a valid chain
- Whether the round number is within an acceptable window [1](#0-0) 

`validatePerasCert` (lines 350–358) accepts **any** certificate unconditionally — it simply wraps the input with a boost weight and returns `Right`: [2](#0-1) 

`implAddVote` in `PerasVoteDB/Impl.hs` carries a matching TODO at line 172–173 confirming that non-trivial validation logic is still missing from the add path: [3](#0-2) 

The production inbound path for peer-supplied votes, `makePerasVotePoolWriterFromChainDB`, calls `validatePerasVote mkPerasParams sd vote` directly — this is the live code path, not a test stub: [4](#0-3) 

`processVotes` (the inbound handler) calls `validateVote` on each peer-supplied vote, then adds all that pass. Since `validatePerasVote` only checks stake lookup, crafted votes with arbitrary voter IDs and block targets pass this gate: [5](#0-4) 

Once enough crafted votes accumulate in `PerasVoteDB`, `updatePerasRoundVoteStates` triggers `forgePerasCert`, which also has a TODO and performs no validation: [6](#0-5) 

The forged certificate is then submitted to `chainSelSync` via `ChainSelAddPerasCert`, which adds it to `PerasCertDB` and triggers chain selection for the boosted block: [7](#0-6) 

---

### Impact Explanation

A Peras certificate boosts a block's weight in chain selection via `PerasSelectView`. An attacker who can forge a certificate for a block of their choice causes honest nodes to assign that block artificially high weight, making them prefer the attacker's chain over the canonical chain. This is a **chain selection bug** that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

Additionally, because `validatePerasCert` accepts any certificate unconditionally, a peer can directly inject a pre-crafted certificate (not just votes) for any block, with the same effect.

---

### Likelihood Explanation

The attack requires only network access to a node running the Peras object-diffusion mini-protocol. No keys, stake, or operator compromise are needed. The attacker sends a batch of crafted `PerasVote` objects (or a single crafted `PerasCert`) with arbitrary voter IDs and a target block of their choice. The current `validatePerasVote` will accept any vote whose claimed voter ID appears in the stake distribution, regardless of whether the sender actually controls that key. The attack is directly reachable from any unprivileged peer connection.

---

### Recommendation

1. Implement cryptographic signature verification in `validatePerasVote` — verify that the vote's signature was produced by the private key corresponding to the claimed `PerasVoterId`, as tracked in the committee selection context (referenced in the TODO at line 108–110 of `PerasVote.hs`).
2. Implement committee membership and round eligibility checks in `validatePerasVote` — reject votes from voters not selected for the given round's committee.
3. Implement cryptographic certificate validation in `validatePerasCert` — verify the certificate's aggregate signature against the claimed quorum of committee members.
4. Remove the placeholder default implementations and require concrete block types to provide real validation before the Peras mini-protocol is enabled on any network.

---

### Proof of Concept

1. Attacker connects to a node via the Peras vote object-diffusion mini-protocol.
2. Attacker constructs `N` `PerasVote` objects, each claiming a different `PerasVoterId` that appears in the stake distribution, all targeting the same `(roundNo, blockPoint)` for a block the attacker controls.
3. `processVotes` filters out already-seen vote IDs, then calls `validatePerasVote` on each. Since `validatePerasVote` only does `lookupPerasVoteStake`, all votes pass.
4. Each vote is added to `PerasVoteDB` via `implAddVote` → `updatePerasRoundVoteStates`.
5. Once the accumulated `ptvtTotalStake` exceeds the quorum threshold, `votesReachQuorum` returns `Just`, `forgePerasCert` is called (no validation), and a `ValidatedPerasCert` is produced for the attacker's block.
6. The certificate is submitted to `chainSelSync` via `ChainSelAddPerasCert`, boosting the attacker's block in chain selection.
7. The honest node now prefers the attacker's chain over the canonical chain. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L373-385)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L199-260)
```haskell
updatePerasRoundVoteState ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  PerasRoundVoteState blk ->
  Either (UpdateRoundVoteStateError blk) (PerasRoundVoteState blk)
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
    case roundState of
      -- Quorum not yet reached
      state@PerasRoundVoteState
        { prvsState =
          Left
            NoQuorum
              { candidateStates
              }
        } -> do
          let oldCandidateState =
                Map.findWithDefault
                  (freshCandidateVoteState (getPerasVoteTarget vote))
                  (getPerasVoteBlock vote)
                  candidateStates
          candidateOrWinnerState <-
            updateCandidateVoteState cfg vote oldCandidateState
              `onErr` \err ->
                RoundVoteStateForgingCertError err
          case candidateOrWinnerState of
            RemainedCandidate newCandidateState -> do
              -- Quorum still not reached for this round
              let prvsCandidateStates' =
                    Map.insert
                      (getPerasVoteBlock vote)
                      newCandidateState
                      candidateStates
              pure $
                state
                  { prvsState =
                      Left
                        NoQuorum
                          { candidateStates = prvsCandidateStates'
                          }
                  }
            BecameWinner winnerState -> do
              -- Quorum has been reached for the first time here for this round
              let winnerPoint =
                    pvtBlock (ptvtTarget (ptvsVoteTally winnerState))
                  loserStates =
                    candidateToLoser <$> Map.delete winnerPoint candidateStates
              pure $
                PerasRoundVoteState
                  { prvsRoundNo =
                      prvsRoundNo roundState
                  , prvsState =
                      Right
                        Quorum
                          { excessVotes = 0
                          , loserStates = loserStates
                          , winnerState = winnerState
                          }
                  }

```
