### Title
Peras Certificate Validation Unconditionally Accepts All Certificates Without Stake or Signature Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` always returns `Right` — accepting every inbound Peras certificate unconditionally — without verifying voter stake, quorum threshold, or any cryptographic signature. This is the direct analog to the external report's use of `balanceOf` instead of `getVotingPower`: instead of consulting the actual voting-power/stake distribution to authorize a certificate, the check is entirely absent. An unprivileged peer can send a crafted certificate for any block and cause an honest node to apply a Peras boost to it, corrupting chain selection.

---

### Finding Description

The catch-all `BlockSupportsPeras` instance in `SupportsPeras.hs` is the live production code path for all certificate validation:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This function is called directly in the inbound certificate processing pipeline:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- ← always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` partitions results and adds all `Right`-validated certificates to the ChainDB: [3](#0-2) 

The same pattern applies to `validatePerasVote`, which skips all cryptographic checks and only performs a stake-distribution lookup:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [4](#0-3) 

The `getVotingCommitteeForElection` function, which is the intended mechanism for selecting the correct epoch's committee for vote/certificate authorization, is also completely unimplemented:

```haskell
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
``` [5](#0-4) 

The correct design — verifying that voters hold sufficient stake and that quorum is reached — is defined in the `WFALS` and `EveryoneVotes` committee implementations, but these are never invoked from the certificate validation path: [6](#0-5) 

---

### Impact Explanation

**High.** A Peras certificate, once accepted into the ChainDB, applies a `perasWeight` boost to the certified block. This boost directly participates in chain selection. Because `validatePerasCert` always returns `Right`, an unprivileged peer can send a certificate for any block — including a non-canonical or adversarially-chosen one — and cause an honest node to prefer that block over the canonical chain. This is a chain-selection bug triggered by a crafted network message from an unprivileged peer, matching the "High" impact category: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

**High.** The Peras certificate miniprotocol is already wired up and active. Any peer that can establish a connection can send `PerasCert` objects. No special keys, stake, or privileges are required. The attacker only needs to craft a `PerasCert` with a desired `pcCertRound` and `pcCertBoostedBlock` and transmit it. The degenerate instance is the only instance in scope for all block types currently used.

---

### Recommendation

1. Replace the degenerate `validatePerasCert` stub with a real implementation that:
   - Verifies the aggregate BLS signature against the claimed voter set.
   - Checks that the total stake of the signers meets the quorum threshold using the correct epoch's stake snapshot.
   - Validates each voter's eligibility via the `WFALS`/`EveryoneVotes` committee for the election identified by the certificate's round number.

2. Implement `getVotingCommitteeForElection` in `AcrossEpochs.hs` to correctly select `currEpochVotingCommittee` or `prevEpochVotingCommittee` based on the `ElectionId` embedded in the certificate, mirroring the epoch-aware stake lookup that `getVotingPower` provides in the external report's context.

3. Replace the `validatePerasVote` stub with a full check that verifies the vote's cryptographic signature and VRF proof against the committee for the vote's election round.

---

### Proof of Concept

```
1. Attacker connects to a target node as a peer via the Peras certificate
   miniprotocol (ObjectDiffusion).

2. Attacker constructs a PerasCert:
     PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block point> }

3. Attacker sends the certificate to the node.

4. makePerasCertPoolWriterFromChainDB → processCerts calls:
     validatePerasCert mkPerasParams cert
   which unconditionally returns:
     Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

5. processCerts adds the certificate to ChainDB via addPerasCertAsync.

6. The Peras boost (perasWeight) is now associated with the adversarial block.

7. Chain selection uses this boost when comparing candidates, potentially
   causing the node to prefer the adversarially-boosted non-canonical block
   over the honest canonical chain.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L68-74)
```haskell
-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L394-432)
```haskell
-- | Compute the voting power of an eligible committee member
--
-- NOTE: there is a subtle difference between the "Ledger stake" and the "Vote
-- weight" of a given voter. On one hand, the ledger stake is the stake as
-- reflected directly by the ledger stake distribution under consideration. On
-- the other hand, the "Vote" weight refers to the voting power of that voter,
-- i.e., the stake that a voter can effectively contribute to an election,
-- which might be different from their ledger stake depending on their committee
-- membership type:
--   * for a persistent committee member, their vote weight is equal to their
--     ledger stake throughout their entire tenure in the committee, whereas
--   * for a non-persistent committee member, their vote weight (provided that
--     they are actually selected to vote via local sortition) is equal to their
--     ledger stake normalized by the total non-persistent stake.
implEligiblePartyVoteWeight ::
  VotingCommittee crypto WFALS ->
  EligibilityWitness crypto WFALS ->
  VoteWeight
implEligiblePartyVoteWeight committee = \case
  -- Persistent members have their voting power equal to their stake
  WFALSPersistentMember
    _seatIndex
    (LedgerStake stake) ->
      VoteWeight stake
  -- Non-persistent members have their voting power proportional to their
  -- number of seats granted by local sortition and their stake (normalized
  -- by the total non-persistent stake)
  WFALSNonPersistentMember
    _seatIndex
    (LedgerStake stake)
    _vrfOutput
    numSeats ->
      VoteWeight $
        fromIntegral (unLocalSortitionNumSeats (unNonZero numSeats))
          * stake
          / nonPersistentStake
     where
      TotalNonPersistentStake (Cumulative (LedgerStake nonPersistentStake)) =
        totalNonPersistentStake committee
```
