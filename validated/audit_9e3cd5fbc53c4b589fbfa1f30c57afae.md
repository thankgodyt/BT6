### Title
Peras Certificate and Vote Validation Completely Bypassed in Inbound Object Diffusion Pipeline - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (accepts every certificate), and `validatePerasVote` only checks voter-ID presence in the stake distribution without verifying the vote's round number, block target, or cryptographic signature. Both stub implementations are wired directly into the production inbound Object Diffusion pipeline, so any unprivileged peer can inject arbitrary Peras certificates and votes that bypass all quorum/signature checks and influence chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two validation entry points used by the network layer:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk ->
  PerasVoteStakeDistr ->
  PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The sole concrete instance (the "degenerate instance for all blks") implements these as:

**`validatePerasCert`** — unconditionally accepts every certificate:
```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

**`validatePerasVote`** — only checks voter-ID presence in the stake distribution, ignoring round number, block target, and signature:
```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

Both stubs are called directly from the production inbound processing functions. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` to `processCerts`, and `makePerasVotePoolWriterFromChainDB` passes `validatePerasVote mkPerasParams sd vote` to `processVotes`. Certificates that pass validation are forwarded to `ChainDB.addPerasCertAsync`, where they influence chain selection via `vpcCertBoost`.

The analog to the external report is exact:
- External report: `commitReaction` checks `contestants[_gameId][msg.sender]` (membership) but not that `_questionId` belongs to `_gameId`.
- Here: `validatePerasVote` checks voter-ID membership in the stake distribution but not that the vote's `pvVoteRound` or `pvVoteBlock` are valid for the current round/chain. `validatePerasCert` checks nothing at all — the `pcCertBoostedBlock` and `pcCertRound` fields are accepted verbatim from the peer. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**For `validatePerasCert`:** Any unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` (pointing to a non-existent, invalid, or attacker-chosen block) and an arbitrary `pcCertRound`. Because `validatePerasCert` unconditionally returns `Right`, the certificate is accepted, timestamped, and added to the ChainDB via `addPerasCertAsync`. The resulting `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the full Peras chain-selection weight boost. This allows an attacker to make an honest node apply a chain-weight boost to any block of the attacker's choosing — a complete bypass of the Peras certificate quorum/signature requirement and a direct chain-selection manipulation.

**For `validatePerasVote`:** A peer can send votes with any `pvVoteRound` and `pvVoteBlock` as long as the `pvVoteVoterId` appears in the current stake distribution. The vote's round number is never checked against the current round, the block target is never verified to exist on the chain, and no BLS signature is verified. Such votes are accepted, stored, and aggregated toward quorum in `updatePerasRoundVoteStates`, potentially forging a fraudulent certificate. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

The attack path is fully reachable by any unprivileged peer connected via the Object Diffusion mini-protocol. No special keys, stake, or operator access are required. The attacker only needs to:
1. Connect to a node running the Peras-enabled consensus.
2. Send a crafted `PerasCert` (or `PerasVote` with a known voter ID from the public stake distribution) via the Object Diffusion protocol.

The stub implementations are explicitly wired into the production `makePerasCertPoolWriterFromChainDB` and `makePerasVotePoolWriterFromChainDB` functions with `TODO` comments acknowledging they are placeholders. The code is live in the production path. [6](#0-5) [7](#0-6) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation before the Peras-enabled code path is deployed. At minimum, verify:
   - The `pcCertRound` is within the valid range (not in the future, not expired per `perasCertMaxRounds`).
   - The `pcCertBoostedBlock` exists on the node's chain and its slot falls within the claimed round's slot window.
   - The certificate carries a valid aggregate BLS signature from a quorum of eligible committee members (using `CryptoSupportsVotingCommittee.verifyCert`).

2. **`validatePerasVote`**: Extend validation to check:
   - The `pvVoteRound` matches the current active Peras round.
   - The `pvVoteBlock` exists on the chain and its slot is within the candidate slot horizon for the claimed round.
   - The BLS vote signature is valid for the claimed `(pvVoteRound, pvVoteBlock)` pair (using `CryptoSupportsVotingCommittee.verifyVote`).

3. Until these checks are implemented, the Object Diffusion inbound pipeline for Peras objects should not be enabled on any network where Peras certificates influence chain selection. [8](#0-7) 

---

### Proof of Concept

A peer sends a single crafted certificate over the Object Diffusion protocol:

```
-- Attacker constructs a PerasCert pointing to an arbitrary block
craftedCert = PerasCert
  { pcCertRound      = PerasRoundNo 999   -- any round
  , pcCertBoostedBlock = someArbitraryBlockPoint  -- any block hash
  }

-- processCerts calls validatePerasCert mkPerasParams craftedCert
-- validatePerasCert unconditionally returns:
--   Right (ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = perasWeight params })
-- The cert is then passed to ChainDB.addPerasCertAsync
-- Chain selection applies vpcCertBoost weight to someArbitraryBlockPoint
```

The receiving node applies the full Peras chain-weight boost to the attacker-chosen block without any quorum or signature verification, potentially causing the node to prefer a non-canonical chain. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Class.hs (L95-122)
```haskell
  -- | Verify a vote cast by a committee member in a given election
  verifyVote ::
    VotingCommittee crypto committee ->
    Vote crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (EligibilityWitness crypto committee)

  -- | Compute the voting weight of a eligibile party
  eligiblePartyVoteWeight ::
    VotingCommittee crypto committee ->
    EligibilityWitness crypto committee ->
    VoteWeight

  -- | Forge a certificate attesting the winner of a given election
  forgeCert ::
    UniqueVotesWithSameTarget crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (Cert crypto committee)

  -- | Verify a certificate attesting the winner of a given election
  verifyCert ::
    VotingCommittee crypto committee ->
    Cert crypto committee ->
    Either
      (VotingCommitteeError crypto committee)
      (NE [EligibilityWitness crypto committee])
```
