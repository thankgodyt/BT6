### Title
Peras Certificate Verification Bypass via Unconditional `validatePerasCert` Stub — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production implementation of `validatePerasCert` in the `BlockSupportsPeras` type class is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Any unprivileged peer can send a crafted `PerasCert` that boosts an arbitrary block by the full `perasWeight`, causing honest nodes to prefer an adversarial chain over the canonical one.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory entry point for Peras certificate validation:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the codebase is the catch-all degenerate instance introduced to make the code compile:

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

The stub:
- Performs **no signature verification** over the certificate's aggregate vote signature.
- Performs **no quorum check** — it does not verify that the certificate represents votes from committee members whose combined stake meets the `perasQuorumStakeThreshold`.
- Performs **no round or slot validation** — it does not check that `pcCertRound` is within the valid window.
- Performs **no voter eligibility check** — it does not verify that the signers were actually elected to the committee for the relevant epoch.
- Unconditionally assigns the full `perasWeight` boost (hardcoded to `15`) to every certificate.

This stub is the active code path. `validatePerasCert` is called directly from the Peras certificate inbound miniprotocol handler (`PerasCert.hs`), from `PerasCertDB/Impl.hs` when persisting certificates, and from `ChainDB/Impl/ChainSel.hs` during chain selection. [2](#0-1) 

The analog to the external report's vulnerability class is direct: just as `VotesToken.sol` has no mint/burn controls — leaving the token supply permanently fixed and uncontrolled — `validatePerasCert` has no validation controls, leaving the "supply" of accepted certificates permanently unlimited and uncontrolled. In both cases, a critical governance parameter (token supply / certificate legitimacy) is frozen in a state that cannot be corrected at runtime.

---

### Impact Explanation

A Peras certificate boosts the chain weight of the block it targets by `perasWeight` (currently `15`). Chain selection in `ChainSel.hs` uses this boosted weight to prefer one chain over another. [3](#0-2) 

Because `validatePerasCert` always returns `Right`, an adversary can:
1. Craft a `PerasCert` pointing `pcCertBoostedBlock` at any block of their choice — including a block on a minority or adversarial fork.
2. Deliver it to an honest node via the certificate miniprotocol.
3. The node stores it as a `ValidatedPerasCert` with full `perasWeight = 15`.
4. Chain selection now treats the adversarial fork as heavier, causing the honest node to switch to it.

This is a **consensus safety failure**: an unprivileged peer with no stake can force an honest node to adopt a non-canonical chain, breaking the fundamental Ouroboros safety guarantee. [4](#0-3) 

---

### Likelihood Explanation

The attack requires only a TCP connection to the node's peer port. No stake, no keys, no privileged access is needed. The crafted certificate is a small, well-typed Haskell value (`PerasCert { pcCertRound, pcCertBoostedBlock }`) that any peer can construct and transmit. The miniprotocol handler calls `validatePerasCert` on every inbound certificate before storing it, and the stub unconditionally accepts it. There is no secondary check downstream that would catch an illegitimate certificate. [5](#0-4) 

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:
1. Verifies the aggregate BLS/Mithril-style signature over `(electionId, candidate)` against the aggregated verification keys of the claimed committee members.
2. Checks that the combined stake of the signers meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
3. Validates that `pcCertRound` falls within the current or immediately preceding epoch's valid round window.
4. Verifies each signer's committee eligibility against the `InterEpochVotingCommittee` for the relevant epoch.

Until this is implemented, the Peras certificate miniprotocol should be disabled or gated behind a feature flag so that no inbound certificates are processed. [6](#0-5) 

---

### Proof of Concept

**Private-testnet reproduction sequence:**

1. Start a local Cardano node with Peras enabled.
2. Connect as an unprivileged peer via the node-to-node miniprotocol.
3. Construct a crafted certificate targeting a block on a minority fork:
   ```haskell
   craftedCert = PerasCert
     { pcCertRound    = PerasRoundNo 1
     , pcCertBoostedBlock = adversarialBlockPoint
     }
   ```
4. Transmit the certificate via the Peras certificate object-diffusion miniprotocol.
5. The node calls `validatePerasCert mkPerasParams craftedCert`, which returns:
   ```haskell
   Right ValidatedPerasCert
     { vpcCert = craftedCert
     , vpcCertBoost = PerasWeight 15
     }
   ```
6. The certificate is stored in `PerasCertDB` and applied during chain selection in `ChainSel.hs`.
7. The adversarial fork now has weight boosted by `15`, causing the honest node to switch to it. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-390)
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L61-117)
```haskell
            let certsAfterLastKnown = takeAscMap (fromIntegral limit) certsAfterLastKnownNoLimit
            traverse
              (\loadCertAction -> (vpcCert . forgetArrivalTime) <$> loadCertAction)
              certsAfterLastKnown
    }

makePerasCertPoolReaderFromCertDB ::
  IOLike m =>
  PerasCertDB m blk ->
  ObjectPoolReader PerasRoundNo (PerasCert blk) PerasCertTicketNo m
makePerasCertPoolReaderFromCertDB perasCertDB =
  makePerasCertPoolReader
    (PerasCertDB.getCertsAfter perasCertDB)

makePerasCertPoolReaderFromChainDB ::
  IOLike m =>
  ChainDB m blk ->
  ObjectPoolReader PerasRoundNo (PerasCert blk) PerasCertTicketNo m
makePerasCertPoolReaderFromChainDB chainDB =
  makePerasCertPoolReader
    (ChainDB.getPerasCertsAfter chainDB)

-------------------------------------------------------------------------------
-- Writers
-------------------------------------------------------------------------------

-- | Create a pool writer directly from a 'PerasCertDB'. This is mostly meant
-- for tests against the 'PerasCertDB' in isolation; for actual production use,
-- see 'makePerasCertPoolWriterFromChainDB' which creates a pool writer from the
-- 'ChainDB' with proper handling of chain selection side-effects.
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-132)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L25-74)
```haskell
data InterEpochVotingCommittee crypto committee
  = InterEpochVotingCommittee
  { currEpochVotingCommittee :: !(VotingCommittee crypto committee)
  , prevEpochVotingCommittee :: !(StrictMaybe (VotingCommittee crypto committee))
  }

-- | Construct an inter-epoch committee selection for the first epoch
mkInterEpochVotingCommittee ::
  CryptoSupportsVotingCommittee crypto committee =>
  VotingCommitteeInput crypto committee ->
  Either
    (VotingCommitteeError crypto committee)
    (InterEpochVotingCommittee crypto committee)
mkInterEpochVotingCommittee votingCommitteeInput = do
  votingCommittee <-
    mkVotingCommittee votingCommitteeInput
  pure $
    InterEpochVotingCommittee
      { currEpochVotingCommittee =
          votingCommittee
      , prevEpochVotingCommittee =
          SNothing
      }

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
