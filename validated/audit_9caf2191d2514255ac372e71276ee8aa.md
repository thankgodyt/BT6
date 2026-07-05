### Title
Peras vote validation accepts votes without cryptographic signature verification, allowing any peer to forge votes on behalf of registered pools — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasVote` function in the sole `BlockSupportsPeras` instance performs no cryptographic verification of vote authenticity. The `PerasVote blk` data type carries no signature field, and validation only checks whether the claimed voter ID appears in the stake distribution. Any unprivileged peer can therefore submit votes impersonating any registered pool, bypassing the Peras voting committee authorization entirely.

---

### Finding Description

**Root cause — missing signature field and missing signature check.**

The `PerasVote blk` data type contains only three fields:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- pool key hash, attacker-controlled
  }
``` [1](#0-0) 

There is no signature field. The `validatePerasVote` implementation (the only one in the codebase — a catch-all instance for all block types) then does:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

The check is purely a map lookup: *is this voter ID present in the stake distribution?* There is no cryptographic proof that the submitter controls the private key for that voter ID. The TODO comment on the instance confirms this is the active implementation for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [3](#0-2) 

**Attacker-controlled entry path.**

The Peras vote diffusion miniprotocol (`hPerasVoteDiffusionClient`) is exposed to every connected peer. Inbound votes are processed by `processVotes`, which calls `validatePerasVote` as its sole authorization gate:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

The production handler in `NodeToNode.hs` currently passes `pure (PerasVoteStakeDistr mempty)` — an empty map — which causes every vote to fail validation today. However, the inline TODO explicitly states this placeholder will be replaced with the real stake distribution:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
--
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

Once that TODO is resolved, the missing signature check becomes immediately exploitable.

**Exploit flow (private-testnet / post-TODO-fix):**

1. Attacker connects to a node via the Peras vote diffusion miniprotocol.
2. Attacker crafts `PerasVote` messages with `pvVoteVoterId` set to any registered pool's key hash.
3. `validatePerasVote` finds the voter ID in the stake distribution and returns `Right (ValidatedPerasVote … stake)` — no signature required.
4. `processVotes` adds the vote to the pool with the impersonated pool's full stake weight.
5. Attacker repeats across multiple registered pool IDs until `votesReachQuorum` is satisfied.
6. `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a certificate that boosts an attacker-chosen block. [6](#0-5) 

---

### Impact Explanation

**Critical — bypass of Peras voting committee authorization enabling unauthorized certificate acceptance.**

An unprivileged peer with a network connection can impersonate any number of registered stake pools in the Peras voting protocol. By accumulating enough forged votes to meet the quorum threshold, the attacker causes the node to forge and accept a Peras certificate boosting an arbitrary block. This directly undermines the Peras chain-quality guarantee: the boosted block gains a weight advantage in chain selection regardless of whether it was produced by a legitimate slot leader, enabling a chain-selection attack without requiring any stake or cryptographic keys.

---

### Likelihood Explanation

**Currently suppressed; becomes high upon the documented TODO fix.** The production handler hard-codes an empty stake distribution, so all inbound votes are rejected today. The code comment explicitly acknowledges this is a temporary placeholder and that the real stake distribution will be wired in. The vulnerability is therefore one code change away from being fully exploitable by any peer. In a private testnet that already wires in a real stake distribution (the intended configuration for Peras testing), it is exploitable right now.

---

### Recommendation

1. Add a cryptographic signature field to `PerasVote blk` (e.g., a BLS or KES signature over `(pvVoteRound, pvVoteBlock, pvVoteVoterId)`).
2. In `validatePerasVote`, verify the signature against the voter's public key retrieved from the stake distribution before accepting the vote.
3. Align with the existing `implVerifyVote` pattern in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs`, which both call `verifyVoteSignature` as a mandatory step before returning an `EligibilityWitness`. [7](#0-6) 

---

### Proof of Concept

```haskell
-- Attacker constructs a vote claiming to be pool "victimPoolId"
-- No private key required — the PerasVote type has no signature field.
let forgedVote = PerasVote
      { pvVoteRound   = currentRound
      , pvVoteBlock   = targetBlock   -- block attacker wants to boost
      , pvVoteVoterId = victimPoolId  -- any registered pool's key hash
      }

-- validatePerasVote only does a map lookup:
--   lookupPerasVoteStake forgedVote realStakeDistr
--   => Just (victimPool's stake)   -- passes!
-- No signature is checked.

-- Repeat for enough pool IDs to exceed the quorum threshold.
-- The PerasVoteDB will then call forgePerasCert, producing a
-- certificate that boosts targetBlock in chain selection.
``` [2](#0-1) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-270)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-410)
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
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-212)
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
        -- Added vote but did not generate a new certificate, either
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
