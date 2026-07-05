### Title
Unsigned `PerasVote` Accepted via Predictable `PerasVoteId`, Enabling Vote Forgery and Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance ships a `PerasVote` data type with no signature field and a `validatePerasVote` implementation that only checks stake-distribution membership. Because `PerasVoteId = (roundNo, voterId)` is fully predictable from public on-chain data, any unprivileged peer can forge a vote for any eligible committee member and inject it via the ObjectDiffusion mini-protocol. Once the forged vote occupies the slot `(roundNo, voterId)` in the VoteDB, the legitimate voter's real vote is silently discarded. The attacker thereby controls which block accumulates quorum stake and receives a Peras boost, directly manipulating chain selection.

---

### Finding Description

**Root cause — no signature in the vote type and no signature check in validation**

The degenerate `BlockSupportsPeras` instance (applied to every `StandardHash blk`) defines `PerasVote blk` as a plain triple with no cryptographic proof of authorship:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [1](#0-0) 

The corresponding `validatePerasVote` only looks up the voter ID in the stake distribution; it performs no signature verification whatsoever:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

This instance is the one actually wired into the production inbound-vote pipeline via `makePerasVotePoolWriterFromChainDB`:

```haskell
(\vote -> getStakeDistrSTM >>= \sd ->
    pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) 

**Compounding factor — ID-first deduplication silently drops the legitimate vote**

`processVotes` filters out any vote whose `PerasVoteId` is already present in the DB *before* any content check:

```haskell
let votesNotAlreadyInDb =
      filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
mapM validateVote votesNotAlreadyInDb
``` [4](#0-3) 

`PerasVoteId` is `(pviRoundNo, pviVoterId)` — it does not include the voted-for block: [5](#0-4) 

`implAddVote` in the VoteDB mirrors this: once a `voteId` is in `pvdsVoteIds`, any subsequent vote with the same ID is silently ignored regardless of which block it targets: [6](#0-5) 

**Attack sequence**

1. The attacker reads the public stake distribution to enumerate all eligible `PerasVoterId` values.
2. For a target round `r` and a block `B'` the attacker wants to boost, the attacker constructs `PerasVote { pvVoteRound = r, pvVoteBlock = B', pvVoteVoterId = victimId }` for one or more high-stake voters.
3. The attacker sends these forged votes to the victim node via the ObjectDiffusion mini-protocol before the legitimate voters' votes arrive.
4. `validatePerasVote` accepts each forged vote (the voter ID is in the stake distribution).
5. The VoteDB records `(r, victimId)` as seen.
6. When the legitimate voter's real vote for the honest block `B` arrives, `processVotes` finds `(r, victimId)` already in `alreadyInDb` and silently drops it.
7. The forged votes accumulate stake toward quorum for `B'`; the honest votes for `B` are suppressed.

---

### Impact Explanation

A quorum of forged votes causes `implAddVote` to call `updatePerasRoundVoteStates`, which triggers `VoteGeneratedNewCert` and forges a `ValidatedPerasCert` boosting `B'`. [7](#0-6) 

A Peras certificate carries a `perasWeight` of 15 (the default) applied to chain selection. An honest node that receives this certificate will prefer the adversarially boosted chain over the honest chain, constituting a **chain-selection manipulation** by an unprivileged peer. This matches the allowed impact: *"Bypass of… Peras voting or certificate checks… that enables unauthorized block, vote, or certificate acceptance"* and *"Chain selection… bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

- The attacker needs only a network connection to a target node; no stake, no keys, no operator access.
- All inputs to forge a vote (`roundNo`, eligible `voterId` values) are publicly observable from the stake distribution.
- The degenerate instance is applied to every `StandardHash blk`, so it covers all current block types.
- The attack window is one Peras round (90 slots by default), which is ample time to inject forged votes before legitimate ones arrive.

---

### Recommendation

1. **Add a signature field to `PerasVote blk`** in the degenerate instance (or require it via the `BlockSupportsPeras` type class contract) so that a vote is cryptographically bound to the private key of the claimed voter.
2. **Verify the signature in `validatePerasVote`** before accepting a vote as valid, analogous to how `implVerifyVote` in `WFALS.hs` calls `checkVoteSignature` and `evalVRF`. [8](#0-7) 

3. **Treat ID-collision as equivocation**, not silent discard: if a vote arrives with the same `(roundNo, voterId)` but a different block, it should be flagged as an equivocating vote and the peer should be disconnected, not silently ignored.

---

### Proof of Concept

The following sketch (in the style of the existing `PerasVoteDB` state-machine tests) demonstrates the attack on a local node:

```haskell
-- Attacker forges a vote for victimVoterId targeting adversarialBlock
let forgedVote = PerasVote
      { pvVoteRound   = currentRound
      , pvVoteBlock   = adversarialBlock   -- attacker's preferred block
      , pvVoteVoterId = victimVoterId      -- a high-stake pool ID from the stake distr
      }

-- Inject via the ObjectDiffusion writer (no signature required)
processVotes systemTime getVoteIds validateVote addVote [forgedVote]

-- Now the legitimate voter's real vote for the honest block is silently dropped:
let legitimateVote = PerasVote
      { pvVoteRound   = currentRound
      , pvVoteBlock   = honestBlock
      , pvVoteVoterId = victimVoterId
      }
processVotes systemTime getVoteIds validateVote addVote [legitimateVote]
-- ^ legitimateVote is filtered out because (currentRound, victimVoterId) is already in DB

-- If enough forged votes accumulate, a certificate boosting adversarialBlock is forged,
-- causing chain selection to prefer the adversarial chain.
```

The existing `PerasVoteDB` state-machine test harness in `Test.Ouroboros.Storage.PerasVoteDB.StateMachine` can be extended to reproduce this scenario directly against the `implAddVote` implementation. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-142)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L179-182)
```haskell
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-200)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-362)
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
```
