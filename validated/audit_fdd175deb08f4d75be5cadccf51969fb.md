### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate Without Performing Any Checks - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` default instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This is the direct analog of the `EarlyZEROVesting` missing-prerequisite bug: just as `startVesting` was missing the `approve` call that `vesting.mint` required, `validatePerasCert` is missing the entire body of validation that its callers assume has been performed before a `ValidatedPerasCert` is produced. Any unprivileged peer can submit a crafted `PerasCert` that will be accepted and used to boost chain weight without any signature, quorum, or eligibility check.

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` instance for all `StandardHash blk` types provides the following implementation:

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

The function signature promises to validate a `PerasCert blk` and return either a `PerasValidationErr` or a `ValidatedPerasCert`. The `ValidatedPerasCert` wrapper is the type-level proof that validation has occurred; downstream chain-selection code trusts this proof. However, the implementation skips every check — aggregate BLS signature verification, quorum threshold, voter eligibility, round number bounds — and wraps the raw certificate unconditionally.

The same pattern applies to `validatePerasVote`: it looks up the voter in the stake distribution but never verifies the vote's BLS signature, meaning a peer can forge votes for any registered pool. [2](#0-1) 

The inbound vote processing path in `processVotes` calls `validatePerasVote` and, on success, stores the vote and potentially triggers certificate assembly and chain-selection boosting: [3](#0-2) 

The `ValidatedPerasCert` produced by the stub `validatePerasCert` carries a `vpcCertBoost` equal to `perasWeight params`, which is the full Peras chain-weight boost. This boost is applied during chain selection, meaning a forged certificate directly influences which chain the node considers canonical. [4](#0-3) 

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification.**

An unprivileged peer can:
1. Craft a `PerasCert` for any block hash and any round number.
2. Send it via the Peras object-diffusion miniprotocol.
3. The receiving node calls `validatePerasCert`, which returns `Right` unconditionally.
4. The node applies the full `perasWeight` boost to the attacker-chosen block during chain selection.

This allows an adversary with no stake and no cryptographic keys to make an honest node prefer an attacker-chosen (potentially invalid or minority) chain over the canonical chain, constituting a consensus safety failure reachable by any unprivileged network peer. [5](#0-4) 

### Likelihood Explanation

The `BlockSupportsPeras` default instance is the only instance in the repository. No Cardano-specific override exists that replaces it with a real implementation. Any node that activates the Peras object-diffusion miniprotocol will use this stub. The attacker entry point is the standard node-to-node Peras vote/cert diffusion channel, reachable by any peer without privileged credentials. [6](#0-5) 

### Recommendation

Replace the stub `validatePerasCert` body with the full validation sequence required by the Peras specification:
1. Verify that all listed voters are eligible committee members for the claimed round.
2. Verify the aggregate BLS signature over `(electionId, candidate)` using the aggregated public keys of the listed voters.
3. Verify that the total stake of the listed voters meets the quorum threshold from `PerasCfg`.
4. Verify that the certificate's round number is within the valid window relative to the current chain tip.

Until this is implemented, the Peras object-diffusion miniprotocol should be disabled or gated behind a feature flag that is off by default in production builds, so that the stub instance is never reachable from an untrusted peer. [7](#0-6) 

### Proof of Concept

1. Connect to a node that has the Peras miniprotocol enabled.
2. Construct a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash (e.g., the attacker's minority-chain tip).
3. Send the certificate via the Peras object-diffusion channel.
4. The node calls `validatePerasCert params cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` without inspecting any field of `cert`.
5. The node stores the `ValidatedPerasCert` and applies the full `perasWeight` boost to the attacker-chosen block during the next chain-selection round.
6. If the boosted block is on a fork, the node may switch to the attacker's chain, diverging from the honest majority.

The root cause is structurally identical to the `EarlyZEROVesting` bug: a function that is supposed to perform a mandatory prerequisite step (`approve` / signature verification) before delegating to a downstream component simply omits that step entirely, causing the downstream component (`vesting.mint` / chain selection) to operate on unvalidated input. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-308)
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

  forgePerasCert ::
    PerasCfg blk ->
    ValidatedPerasVotesWithQuorum blk ->
    Either (PerasForgeErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L121-152)
```haskell
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
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
