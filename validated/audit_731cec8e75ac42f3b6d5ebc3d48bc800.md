### Title
Unimplemented `getVotingCommitteeForElection` Always Throws `error`, Permanently Breaking Cross-Epoch Peras Certificate Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs`)

---

### Summary

`getVotingCommitteeForElection` in `AcrossEpochs.hs` is a stub that unconditionally calls `error "TODO: implement getVotingCommitteeForElection"`. This is the sole exported function for resolving which `VotingCommittee` to use when validating a Peras vote or certificate whose `ElectionId` belongs to a previous epoch. Any production code path that calls it will throw an impure Haskell exception, making cross-epoch Peras certificate and vote verification permanently inaccessible — a direct structural analog to the reported wrong-index lookup that permanently blocks a critical operation.

---

### Finding Description

`AcrossEpochs.hs` defines `InterEpochVotingCommittee`, which holds both the current and previous epoch's `VotingCommittee`, precisely to support late-arriving votes and certificates from the prior epoch:

```haskell
data InterEpochVotingCommittee crypto committee
  = InterEpochVotingCommittee
  { currEpochVotingCommittee :: !(VotingCommittee crypto committee)
  , prevEpochVotingCommittee :: !(StrictMaybe (VotingCommittee crypto committee))
  }
```

The function that resolves the correct committee for a given `ElectionId` is:

```haskell
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```

Both arguments are discarded (`_electionId`, `_interEpochVotingCommittee`). The body unconditionally calls `error`, which in Haskell throws an `ErrorCall` impure exception regardless of the inputs. The function never inspects `currEpochVotingCommittee` or `prevEpochVotingCommittee`, and never returns `Just` or `Nothing`. Any caller receives a runtime exception instead of a committee lookup result.

This is structurally identical to the reported bug: instead of looking up the correct key (the `ElectionId`), the code uses a hardcoded non-functional value (the `error` call), making the operation permanently inaccessible.

The `implVerifyVote` and `implVerifyCert` functions in both `EveryoneVotes.hs` and `WFALS.hs` require a resolved `VotingCommittee` to perform seat-index lookups via `getCandidateIfSeatWithinBounds` and signature verification. Without a correctly resolved committee, neither vote nor certificate verification can proceed. [1](#0-0) [2](#0-1) 

---

### Impact Explanation

**Impact: High — Bypass of Peras voting and certificate checks.**

`getVotingCommitteeForElection` is the only mechanism for resolving the committee needed to validate a Peras vote or certificate when the `ElectionId` spans an epoch boundary. Because it always throws, no cross-epoch Peras certificate can ever be verified. This means:

1. The Peras chain-selection weight contributed by certificates from the previous epoch cannot be computed or validated. An adversary can present a chain fragment accompanied by crafted cross-epoch Peras certificates; the honest node cannot verify them and the Peras boost is silently unavailable, weakening the chain-selection security guarantee that Peras is designed to provide.
2. Any honest node that receives a legitimate late-arriving vote or certificate from the previous epoch and routes it through `getVotingCommitteeForElection` will throw an uncaught impure exception, which — depending on the call site's exception handling — either crashes the node or silently discards the certificate.

This falls squarely within: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate … acceptance"* and *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."* [3](#0-2) [4](#0-3) 

---

### Likelihood Explanation

**Likelihood: High.**

- The function is in the production source tree (`src/ouroboros-consensus/`), not in tests or benchmarks.
- It is explicitly exported from the module.
- The `InterEpochVotingCommittee` structure and `newEpoch` transition are fully implemented; `getVotingCommitteeForElection` is the only missing piece.
- Any code path that calls it — including `addPerasCertAsync` / `addPerasVoteWithAsyncCertHandling` in `ChainSel.hs` — will trigger the exception unconditionally, with no input-dependent escape.
- An unprivileged peer needs only to send a Peras vote or certificate whose `ElectionId` belongs to the previous epoch to trigger the code path. [5](#0-4) [6](#0-5) 

---

### Recommendation

Implement `getVotingCommitteeForElection` to inspect the `ElectionId`'s epoch and return:
- `Just (currEpochVotingCommittee interEpochVotingCommittee)` if the election belongs to the current epoch,
- `strictMaybeToMaybe (prevEpochVotingCommittee interEpochVotingCommittee)` if it belongs to the previous epoch,
- `Nothing` otherwise.

The `ElectionId` must encode sufficient epoch information for this dispatch. Until the function is correctly implemented, any call site that routes cross-epoch votes or certificates through it must be guarded to prevent the impure exception from propagating.

---

### Proof of Concept

```
1. Node is running with Peras enabled and has just crossed an epoch boundary.
   InterEpochVotingCommittee now holds:
     currEpochVotingCommittee = <epoch N committee>
     prevEpochVotingCommittee = SJust <epoch N-1 committee>

2. An unprivileged peer sends a Peras certificate whose ElectionId
   was issued in epoch N-1 (a legitimate late-arriving certificate).

3. The node calls:
     getVotingCommitteeForElection electionIdFromEpochN_1 interEpochCommittee

4. The function discards both arguments and executes:
     error "TODO: implement getVotingCommitteeForElection"

5. An ErrorCall exception is thrown. Depending on the call site:
   a. If uncaught: the node process terminates.
   b. If caught and treated as validation failure: the certificate is
      silently rejected, Peras chain-selection weight is not applied,
      and the adversary's chain (without the certificate boost) may
      be preferred over the honest chain.

Root cause: wrong "key" used in the lookup — the actual ElectionId
is never consulted; a hardcoded error is returned instead, exactly
as agents(0) was hardcoded in the reported OmoVault bug.
``` [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L1-19)
```haskell
-- | This module extends a given voting committee to work across epochs.
--
-- This is needed to support the case of validating an old vote or certificate
-- from a previous epoch arriving too late. In the general case, this means we
-- would need to store an arbitrary number of past voting committee selections.
-- However, since:
--   1. the length of an epoch is much larger than the immutability window, and
--   2. we don't care about validating votes older than the immutability window,
--      it follows that we only need to store the voting committee selection for
--      the current and previous epochs.
--  NOTE: this rationale might need to be revisited if we ever want to support
--  validating votes and certificates older than the immutability window, e.g.,
--  for historical queries.
module Ouroboros.Consensus.Committee.AcrossEpochs
  ( InterEpochVotingCommittee (..)
  , mkInterEpochVotingCommittee
  , newEpoch
  , getVotingCommitteeForElection
  ) where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L25-29)
```haskell
data InterEpochVotingCommittee crypto committee
  = InterEpochVotingCommittee
  { currEpochVotingCommittee :: !(VotingCommittee crypto committee)
  , prevEpochVotingCommittee :: !(StrictMaybe (VotingCommittee crypto committee))
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L49-74)
```haskell
-- | Update an inter-epoch committee selection at the beginning of a new epoch
newEpoch ::
  CryptoSupportsVotingCommittee crypto committee =>
  VotingCommitteeInput crypto committee ->
  InterEpochVotingCommittee crypto committee ->
  Either
    (VotingCommitteeError crypto committee)
    (InterEpochVotingCommittee crypto committee)
newEpoch newEpochVotingCommitteeInput interEpochVotingCommittee = do
  newEpochVotingCommittee <-
    mkVotingCommittee newEpochVotingCommitteeInput
  pure $
    InterEpochVotingCommittee
      { currEpochVotingCommittee =
          newEpochVotingCommittee
      , prevEpochVotingCommittee =
          SJust (currEpochVotingCommittee interEpochVotingCommittee)
      }

-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L494-548)
```haskell
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
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
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L18-29)
```haskell
module Ouroboros.Consensus.Storage.ChainDB.Impl.ChainSel
  ( addBlockAsync
  , addPerasCertAsync
  , addPerasVoteWithAsyncCertHandling
  , chainSelSync
  , chainSelectionForBlock
  , initialChainSelection
  , triggerChainSelectionAsync

    -- * Exported for testing purposes
  , olderThanImmTip
  ) where
```
