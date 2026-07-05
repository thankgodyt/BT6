### Title
Peras Vote Validation Stub Omits BLS Signature and VRF Eligibility Verification, Enabling Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation — the only concrete instance of `BlockSupportsPeras` in the repository — does not verify the BLS vote signature or VRF eligibility proof. It only checks whether the voter's ID appears in the stake distribution map. The vote diffusion handler in `NodeToNode.hs` currently passes an empty stake distribution (causing all votes to be rejected), but this is an explicitly acknowledged temporary placeholder, not a security control. Once the stake distribution is properly wired in as planned, any unprivileged peer who knows a valid committee member's voter ID (public information) can submit forged votes on their behalf, accumulate enough stake to reach quorum for any block, and cause the node to forge and accept an invalid Peras certificate — directly manipulating chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `SupportsPeras.hs` defines `validatePerasVote` as the mandatory entry point for vote validation before a vote is admitted to the `PerasVoteDB`. The only concrete implementation in the repository is the degenerate instance explicitly marked as a placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [1](#0-0) 

This implementation accepts any vote whose `PerasVoterId` appears in the stake distribution. It does **not** verify:
1. The BLS vote signature (`pvSignature` in the concrete `PerasVote` type in `V1.hs`)
2. The VRF eligibility proof (`pvEligibilityProof`)
3. Round or block validity

The concrete `PerasVote` type in `V1.hs` carries both a `pvSignature :: VoteSignature PerasBLSCrypto` and a `pvEligibilityProof :: PerasVoteEligibilityProof`, and the `CryptoSupportsVoteSigning` interface in `Crypto.hs` provides `verifyVoteSignature`. These are never called by the stub. [2](#0-1) 

The production vote diffusion handler in `NodeToNode.hs` wires this stub into the live miniprotocol path via `makePerasVotePoolWriterFromChainDB`, passing `(pure (PerasVoteStakeDistr mempty))` as the stake distribution:

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
``` [3](#0-2) 

The comment is explicit: the empty map is a temporary workaround, not a security boundary. `makePerasVotePoolWriterFromChainDB` calls `processVotes`, which calls `validatePerasVote mkPerasParams sd vote` in an STM transaction: [4](#0-3) 

`processVotes` then passes each validated vote to `ChainDB.addPerasVoteWithAsyncCertHandling`, which calls `implAddVote`. `implAddVote` calls `updatePerasRoundVoteStates`, which accumulates stake and calls `votesReachQuorum` → `forgePerasCert` when the quorum threshold is crossed: [5](#0-4) 

There is also a separate TODO in `implAddVote` itself acknowledging that non-trivial validation logic is still missing: [6](#0-5) 

---

### Impact Explanation

Once the stake distribution is properly wired in (replacing the empty placeholder), an unprivileged peer can:

1. Read the current committee members' `PerasVoterId` values from the stake distribution (public information).
2. Construct `PerasVote` messages with valid voter IDs but arbitrary/forged BLS signatures and VRF proofs.
3. Submit these via the `PerasVoteDiffusion` miniprotocol. `validatePerasVote` will accept them because `lookupPerasVoteStake vote stakeDistr` returns `Just stake` for any known voter ID, regardless of signature.
4. Repeat for enough committee members to exceed the quorum threshold (`stakeAboveThreshold`).
5. `updateCandidateVoteState` → `votesReachQuorum` → `forgePerasCert` forges a `ValidatedPerasCert` for an attacker-chosen block.
6. The certificate is added to the ChainDB and used by chain selection to boost the attacker's block, causing the honest node to prefer a non-canonical or attacker-controlled chain.

This is a bypass of vote signature validation enabling unauthorized certificate acceptance — matching the **Critical** impact category: "Bypass of... certificate/signature validation... that enables unauthorized block, vote, or certificate acceptance." [7](#0-6) 

---

### Likelihood Explanation

The vulnerability is currently gated by the empty stake distribution in `NodeToNode.hs`, which causes `lookupPerasVoteStake` to always return `Nothing`, rejecting all votes. However, the code comment explicitly states this is a temporary workaround pending proper plumbing. The moment the stake distribution is wired in — a planned, necessary step for Peras to function — the signature-less `validatePerasVote` stub becomes the live validation gate for all inbound votes from any peer. No special privileges, leaked keys, or stake majority are required; only knowledge of committee member voter IDs, which are derivable from the public stake distribution.

---

### Recommendation

Implement actual BLS signature verification and VRF eligibility proof verification inside `validatePerasVote` **before** replacing the empty stake distribution with a real one. The `PerasVote` type in `V1.hs` already carries `pvSignature` and `pvEligibilityProof`. The `CryptoSupportsVoteSigning.verifyVoteSignature` and `CryptoSupportsVRF.evalVRF` interfaces in `Crypto.hs` provide the necessary primitives. The `WFALS.hs` module already demonstrates correct vote and certificate verification using these interfaces and should serve as the reference implementation. [8](#0-7) 

---

### Proof of Concept

1. Connect to a node with a non-empty stake distribution (post-TODO fix in `NodeToNode.hs`).
2. Read committee member voter IDs from the stake distribution.
3. Construct a `PerasVote` with a valid `pvVoteVoterId` but a forged `pvSignature` and arbitrary `pvEligibilityProof`.
4. Send the vote via the `PerasVoteDiffusion` miniprotocol.
5. `processVotes` calls `validatePerasVote mkPerasParams sd vote`; `lookupPerasVoteStake` returns `Just stake` because the voter ID is in the distribution — the vote is accepted as `ValidatedPerasVote` with no signature check.
6. Repeat for enough distinct committee member IDs to satisfy `stakeAboveThreshold`.
7. `updateCandidateVoteState` calls `votesReachQuorum`, which returns `Just votesWithQuorum`.
8. `forgePerasCert` produces a `ValidatedPerasCert` for the attacker's chosen block.
9. The certificate is stored in the ChainDB and applied to chain selection, causing the node to boost and prefer the attacker's block over the honest chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-246)
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
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L577-587)
```haskell
updateCandidateVoteState cfg vote oldState =
  let
    newVoteTally = updateTargetVoteTally vote (ptvsVoteTally oldState)
    voteList = forgetArrivalTime <$> Map.elems (ptvtVotes newVoteTally)
   in
    case votesReachQuorum cfg voteList of
      Just votesWithQuorum -> do
        cert <- forgePerasCert cfg votesWithQuorum
        pure $ BecameWinner (PerasTargetVoteWinner newVoteTally cert)
      Nothing -> do
        pure $ RemainedCandidate (PerasTargetVoteCandidate newVoteTally)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L599-616)
```haskell
-- | Check the validity of a vote signature
checkVoteSignature ::
  forall crypto.
  CryptoSupportsVoteSigning crypto =>
  VoteVerificationKey crypto ->
  ElectionId crypto ->
  VoteCandidate crypto ->
  VoteSignature crypto ->
  Either
    (VotingCommitteeError crypto WFALS)
    ()
checkVoteSignature verificationKey electionId message sig =
  bimap InvalidVoteSignature id $ do
    verifyVoteSignature
      verificationKey
      electionId
      message
      sig
```
