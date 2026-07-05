### Title
Peras Vote Signature Validation Bypass in Stub `validatePerasVote` Enables Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default catch-all `BlockSupportsPeras` instance's `validatePerasVote` implementation only checks whether a voter ID exists in the stake distribution, but performs no cryptographic signature verification. The `PerasVote` data type in this instance carries no signature field at all. An unprivileged peer can send crafted votes claiming any known voter identity, bypass validation, accumulate quorum, and cause the node to forge a Peras certificate for an attacker-chosen block — directly influencing chain selection via the Peras weight boost.

### Finding Description

The `BlockSupportsPeras` class in `SupportsPeras.hs` defines `validatePerasVote` as the gate for all inbound Peras votes. The only deployed instance is the explicit catch-all stub:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  data PerasVote blk = PerasVote
    { pvVoteRound  :: PerasRoundNo
    , pvVoteBlock  :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [1](#0-0) 

Two critical defects are present simultaneously:

1. **The `PerasVote blk` data type has no signature field.** The vote carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId`. There is no `pvSignature` or eligibility proof. Signature verification is structurally impossible with this type.

2. **`validatePerasVote` only checks stake distribution membership.** It calls `lookupPerasVoteStake vote stakeDistr` — if the voter ID is in the distribution, the vote is unconditionally accepted as `ValidatedPerasVote`. No round-number check, no block-hash check, no cryptographic proof.

Similarly, `validatePerasCert` always returns `Right` unconditionally, accepting any certificate from any peer:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [2](#0-1) 

**Inbound production path** — the stub is called directly from production vote-ingestion code:

```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          (\vote -> getStakeDistrSTM >>= \sd ->
              pure $ validatePerasVote mkPerasParams sd vote)
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    ...
    }
``` [3](#0-2) 

`processVotes` validates each inbound vote via the injected `validateVote` callback, then adds all passing votes to the pool: [4](#0-3) 

Once votes are added, `implAddVote` calls `updatePerasRoundVoteStates`, which forges a `ValidatedPerasCert` when quorum is reached: [5](#0-4) 

The forged certificate is then handled by `ChainDB.addPerasVoteWithAsyncCertHandling`, which feeds it into chain selection where it applies the Peras weight boost (`vpcCertBoost = perasWeight params`) to the attacker-chosen block.

**Analogy to esFLUO:** In esFLUO, `deposit(user, amount)` accepted any caller-supplied `user` address and `amount = 0`, resetting the victim's vesting timestamp. Here, `validatePerasVote` accepts any peer-supplied voter ID without a signature, resetting the quorum accumulation toward an attacker-chosen block — the same pattern of unsolicited state modification via missing input validation.

### Impact Explanation

**Critical — Bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance.**

An unprivileged peer can:
1. Enumerate valid voter IDs from the public stake distribution.
2. Craft `PerasVote` messages with those IDs, any `pvVoteRound`, and any `pvVoteBlock` (attacker-chosen block hash).
3. Send enough such votes to reach quorum.
4. Cause the target node to forge a `ValidatedPerasCert` for the attacker-chosen block.
5. That certificate applies a Peras weight boost to the attacker's block in chain selection, potentially causing the node to prefer a non-canonical chain.

This directly violates the Peras security property that only legitimately elected committee members with valid cryptographic proofs may cast votes.

### Likelihood Explanation

**High.** Voter IDs (`PerasVoterId`, a key hash) are derived from the public stake distribution, which is observable on-chain. No private keys, admin access, or stake majority is required. The attacker needs only a network connection to the target node and knowledge of the ObjectDiffusion mini-protocol message format. The attack is deterministic and repeatable.

### Recommendation

1. **Require a signature field in `PerasVote blk`.** The concrete `V1.PerasVote` type already carries `pvSignature :: VoteSignature PerasBLSCrypto` and `pvEligibilityProof`. The default instance's `PerasVote blk` must be replaced or the class must enforce a signature field. [6](#0-5) 

2. **Implement full `validatePerasVote` before enabling the inbound vote path.** Validation must verify: (a) cryptographic signature against the voter's public key from the committee, (b) round number matches the current Peras round, (c) voted block is a known valid block, (d) eligibility proof (VRF for non-persistent members).

3. **Implement full `validatePerasCert` before enabling the inbound certificate path.** The current stub unconditionally returns `Right` for every certificate.

4. **Gate `makePerasVotePoolWriterFromChainDB` behind a feature flag** that is disabled until the proper `BlockSupportsPeras` instance with real validation is deployed.

### Proof of Concept

**Setup:** A private testnet running any Cardano node that has the ObjectDiffusion Peras vote mini-protocol enabled.

**Steps:**

1. Query the stake distribution to obtain a set of valid `PerasVoterId` values (key hashes of committee members).
2. Construct `PerasVote blk` messages with:
   - `pvVoteRound` = current Peras round number
   - `pvVoteBlock` = point of an attacker-chosen block (e.g., a minority-chain block)
   - `pvVoteVoterId` = any valid voter ID from step 1
3. Send enough such votes (≥ quorum threshold) to the target node via the ObjectDiffusion mini-protocol.
4. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each vote; each passes because `lookupPerasVoteStake vote stakeDistr` returns `Just stake` for the valid voter ID.
5. `implAddVote` → `updatePerasRoundVoteStates` detects quorum reached → `forgePerasCert` produces a `ValidatedPerasCert` for the attacker-chosen block.
6. `ChainDB.addPerasVoteWithAsyncCertHandling` feeds the certificate into chain selection.
7. **Expected outcome:** The target node's chain selection applies the Peras weight boost to the attacker-chosen block, potentially switching to a non-canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-217)
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
