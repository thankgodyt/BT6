### Title
`validatePerasVote` Accepts Self-Declared `pvVoteVoterId` Without Signature Verification, Enabling Deduplication-State Poisoning to Suppress Legitimate Votes — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` default instance accepts any vote whose `pvVoteVoterId` field appears in the stake distribution, without verifying a cryptographic signature binding that voter ID to the actual sender. Because the per-round deduplication set (`pvdsVoteIds`) is keyed on the self-declared `pvVoteVoterId`, an unprivileged peer can send a crafted vote claiming to be from any legitimate voter, permanently occupying that voter's slot in the deduplication set. When the real voter later submits their genuine vote, it is silently dropped as `PerasVoteAlreadyInDB`, preventing quorum from being reached and suppressing the Peras weight boost for the targeted round.

---

### Finding Description

**Root cause — `validatePerasVote` trusts the self-declared voter identity**

The catch-all `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasVote` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [1](#0-0) 

`lookupPerasVoteStake` resolves the stake purely from the vote's own `pvVoteVoterId` field:

```haskell
lookupPerasVoteStake vote distr =
  Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)
``` [2](#0-1) 

`pvVoteVoterId` is a plain data field in the wire-format `PerasVote` record — it is not bound to any signing key by the validation logic:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- self-declared, never verified
  }
``` [3](#0-2) 

**Deduplication keyed on the unverified identity**

`processVotes` (the inbound handler called for every batch of peer-supplied votes) filters duplicates using `getPerasVoteId`, which derives the vote ID directly from `pvVoteVoterId`:

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
``` [4](#0-3) 

`implAddVote` then permanently records the vote ID in `pvdsVoteIds`:

```haskell
addOrIgnoreVote pvds voteId
  | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
  | otherwise = tryAddVote pvds voteId
``` [5](#0-4) 

`PerasVoteId` is `(pviRoundNo, pviVoterId)` — both fields come from the vote body, not from a verified key: [6](#0-5) 

**Analog to the external report**

| External report (`AsyncSynthVault`) | This codebase (Peras vote DB) |
|---|---|
| `requestRedeem(shares, receiver, owner)` called by a third party | Peer sends `PerasVote{pvVoteVoterId = victimPool}` |
| `lastRedeemRequestId[owner]` set instead of `lastRedeemRequestId[receiver]` | `pvdsVoteIds` updated with `(round, victimPool)` from the spoofed vote |
| Receiver's `lastRedeemRequestId` stays 0; claim fails | Victim pool's real vote arrives; `Set.member voteId pvdsVoteIds` is `True` → `PerasVoteAlreadyInDB` |
| Shares locked forever | Legitimate vote silently dropped; quorum may not be reached |

**Current partial mitigation**

The production wiring in `NodeToNode.hs` currently passes an empty stake distribution:

```haskell
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [7](#0-6) 

With an empty distribution, `lookupPerasVoteStake` always returns `Nothing`, so every vote fails validation and the deduplication set is never poisoned. However, the same file carries a `TODO` noting that the real stake distribution will be wired in once the Peras plumbing is complete. At that point the mitigation disappears and the attack becomes directly exploitable.

---

### Impact Explanation

Once the stake distribution is populated, an unprivileged peer can suppress the vote of any pool in the distribution for any round by sending one crafted `PerasVote` per target pool per round. If enough legitimate votes are suppressed, the quorum threshold is never crossed, no Peras certificate is forged for that round, and the intended weight boost is not applied to the boosted block. A node that would otherwise have preferred the boosted chain may instead select a competing chain, constituting a chain-selection deviation beyond the intended Peras security assumptions.

This maps to: **High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

---

### Likelihood Explanation

- **Entry path**: any peer connected via the `hPerasVoteDiffusionClient` mini-protocol handler can submit arbitrary `PerasVote` objects; no credentials are required.
- **Trigger condition**: the stake distribution must be non-empty (i.e., the TODO at `cardano-peras/issues/73` and `issues/120` must be resolved). This is an explicit near-term development milestone.
- **Attack cost**: one crafted vote per victim pool per round; trivially automatable.

---

### Recommendation

`validatePerasVote` must verify a cryptographic signature that binds `pvVoteVoterId` to the actual sender before accepting the vote. The `VotingCommittee` abstraction (`WFALS`, `EveryoneVotes`) already demonstrates the correct pattern — `implVerifyVote` looks up the voter's public key from the committee by seat index and calls `verifyVoteSignature` / `evalVRF` before returning an `EligibilityWitness`. [8](#0-7) 

The default `BlockSupportsPeras` instance should either be removed in favour of a concrete Cardano-specific instance that performs full signature verification, or the `validatePerasVote` stub must be completed (per `cardano-peras/issues/120`) before the stake distribution is wired in.

---

### Proof of Concept

```
Precondition: stake distribution is non-empty (post-TODO state).

1. Attacker connects to an honest node as a peer.
2. Attacker sends PerasVote { pvVoteRound = R, pvVoteBlock = B, pvVoteVoterId = victimPool }.
3. processVotes:
     alreadyInDb does not contain (R, victimPool)  →  vote passes dedup filter.
     validatePerasVote: lookupPerasVoteStake finds victimPool in distribution  →  Right (ValidatedPerasVote ...).
     addVote called  →  implAddVote inserts (R, victimPool) into pvdsVoteIds.
4. Legitimate victimPool later sends its real vote for round R.
5. processVotes:
     alreadyInDb contains (R, victimPool)  →  vote filtered out before validation.
     Vote is silently discarded (PerasVoteAlreadyInDB).
6. If enough pools are suppressed this way, quorum is not reached for round R,
   no certificate is forged, and the Peras weight boost is not applied.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-203)
```haskell
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

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-390)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
          Just nonZeroNumSeats ->
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
```
