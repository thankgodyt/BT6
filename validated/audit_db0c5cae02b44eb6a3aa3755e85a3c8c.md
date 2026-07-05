### Title
Peras Vote and Certificate Signature Verification Bypass via Degenerate `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance used for all block types unconditionally accepts Peras votes and certificates without performing any cryptographic signature verification. An unprivileged peer can submit forged votes attributed to any registered voter, and they will be accepted as valid, potentially enabling fraudulent certificate forging and unauthorized chain-selection boosts.

### Finding Description

The `BlockSupportsPeras` typeclass defines two critical validation methods: `validatePerasVote` and `validatePerasCert`. The only concrete instance in the production codebase is the degenerate catch-all instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

The `validatePerasVote` implementation in this instance only checks stake distribution membership — it performs **no signature verification, no VRF eligibility proof check, and no round-specific counter check**:

```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [2](#0-1) 

Similarly, `validatePerasCert` unconditionally returns `Right` for any certificate: [3](#0-2) 

The degenerate `PerasVote blk` data type in this instance carries no signature field at all — the type itself is structurally incapable of carrying a cryptographic proof: [4](#0-3) 

This contrasts with the concrete production vote type `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`, which carries `pvSignature :: !(VoteSignature PerasBLSCrypto)` and `pvEligibilityProof :: !PerasVoteEligibilityProof`, but no corresponding `BlockSupportsPeras` instance exists to validate them. [5](#0-4) 

The inbound vote processing pipeline in `processVotes` calls the `validateVote` callback — which resolves to this degenerate instance — before adding votes to the database: [6](#0-5) 

### Impact Explanation

Peras certificates boost blocks in chain selection by adding `perasWeight` to their score. A fraudulent certificate accepted via forged votes would cause honest nodes to prefer an attacker-chosen block over the canonical chain, constituting a chain-selection manipulation. This maps to the **High** impact category: bypass of Peras certificate/vote signature validation enabling unauthorized certificate acceptance.

### Likelihood Explanation

Any peer participating in the Peras vote diffusion miniprotocol can submit votes. The attacker only needs to know a registered voter's `PerasVoterId` (a public key hash, observable from the stake distribution) to forge a vote that passes `validatePerasVote`. No private key material is required. The barrier is whether Peras vote diffusion is active on the network.

### Recommendation

A concrete `BlockSupportsPeras` instance for production Cardano block types must be implemented that:
1. Verifies the BLS vote signature against the voter's public key and the `(roundNo, boostedBlock)` message.
2. Verifies the VRF eligibility proof for non-persistent committee members.
3. Checks that the voter's seat index is within bounds and that the voter has not already cast a vote for this round (analogous to nonce increment in the UniswapV2 fix).

The degenerate instance should be removed or restricted to test/mock contexts only.

### Proof of Concept

1. Observe the stake distribution to obtain a registered voter's `PerasVoterId` (public key hash).
2. Construct a `PerasVote blk` value using the degenerate instance's data type, setting `pvVoteRound` to the current round and `pvVoteBlock` to an attacker-chosen block point, with the observed `pvVoteVoterId`.
3. Submit this vote to a node via the Peras vote diffusion miniprotocol.
4. `processVotes` calls `validateVote` → `validatePerasVote` → checks only `lookupPerasVoteStake`, which succeeds because the voter ID is in the stake distribution.
5. The vote is added to `PerasVoteDB` as a `ValidatedPerasVote` with the voter's full stake weight.
6. Repeat with additional registered voter IDs until `stakeAboveThreshold` is satisfied, triggering `forgePerasCert` for the attacker-chosen block. [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-217)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

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
```
