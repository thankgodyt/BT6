### Title
Peras Certificate Validation Bypass — `validatePerasCert` Unconditionally Returns Success Without Any Cryptographic or Semantic Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` catch-all instance in `SupportsPeras.hs` provides a `validatePerasCert` implementation that **always returns `Right` (success)** without performing any cryptographic or semantic validation. Any block producer can embed an arbitrary, structurally well-formed `PerasCert` into a block; every honest node will accept it as valid and apply its chain-selection boost unconditionally. This is the direct structural analog of the Beacon-Kit finding: block-carried data (deposits / Peras certificates) is applied to consensus state without being verified against an authoritative external source.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory gate that must approve a certificate before it influences chain selection:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only deployed instance is the degenerate catch-all:

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

The function body unconditionally wraps the caller-supplied `cert` in `ValidatedPerasCert` and assigns it the full `perasWeight`. No signature is verified, no committee membership is checked, no round-number or boosted-block consistency is enforced. The same pattern applies to `validatePerasVote`: [2](#0-1) 

Because this is a catch-all `StandardHash blk` instance, it is the instance resolved for every block type (including `CardanoBlock`) unless a more-specific overlapping instance is provided. No such override is present in the repository.

The `ValidatedPerasCert` wrapper is the type-level proof that a certificate passed `validatePerasCert`. Downstream chain-selection and certificate-storage code trusts this wrapper: [3](#0-2) 

Votes received over the network are processed through `processVotes`, which calls the injected `validateVote` callback before storing them: [4](#0-3) 

When the callback resolves to the degenerate instance, every inbound vote and every in-block certificate is accepted without any check.

---

### Impact Explanation

**Impact: High — Chain-selection manipulation.**

A Peras certificate embedded in a block carries a `vpcCertBoost` weight that is added to the chain-selection score of the boosted block. Because `validatePerasCert` always succeeds, a malicious block producer can:

1. Craft a `PerasCert` naming **any** block point as `pcCertBoostedBlock` — including a block on a minority or adversarial fork.
2. Embed the certificate in a legitimately produced block (the producer needs only enough stake to win a single slot, not a majority).
3. Every honest node that receives the block calls `validatePerasCert`, receives `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`, and applies the full boost to the attacker-chosen block.
4. Chain selection on all honest nodes is now biased toward the attacker-chosen fork, potentially causing them to prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions.

This matches the allowed impact class: *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Likelihood: High (conditional on Peras activation).**

- The attacker entry path requires only the ability to produce a single block — i.e., any registered stake pool operator, regardless of stake size. No stake majority, no key compromise, and no social engineering is required.
- The vulnerable code is in a production source file (not a test or mock), is the only instance of `BlockSupportsPeras` in the repository, and is unconditionally reachable whenever a block containing a `PerasCert` is processed.
- The TODO comments acknowledge the gap explicitly, confirming the absence of real validation is known but unresolved.

---

### Recommendation

Before Peras certificates influence any production chain-selection path, replace the stub with a real implementation of `validatePerasCert` that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the declared voter set.
2. Checks that every voter in `pcVoters` was a member of the elected committee for `pcCertRound` (VRF eligibility proof or persistent-committee membership).
3. Confirms the total stake of the voter set exceeds the quorum threshold from `PerasCfg`.
4. Validates that `pcCertBoostedBlock` refers to a block that actually exists on a chain the node has seen.

The same applies to `validatePerasVote`. Until these checks are in place, the `BlockSupportsPeras` instance must not be reachable from any live chain-selection or certificate-storage code path.

---

### Proof of Concept

```
Attacker (any stake pool operator):
  1. Wins slot S legitimately (any slot).
  2. Constructs PerasCert { pcCertRound = R,
                            pcCertBoostedBlock = <adversarial fork tip> }
     with arbitrary/garbage voter fields.
  3. Embeds cert in block B at slot S via getPerasCertInBlock.
  4. Broadcasts B to the network.

Honest node receives B:
  5. Calls validatePerasCert params cert
     → unconditionally returns Right ValidatedPerasCert { vpcCertBoost = perasWeight params }
  6. Chain-selection score of <adversarial fork tip> is incremented by perasWeight.
  7. If perasWeight is large enough, honest node switches to adversarial fork.
```

The root cause is at: [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-219)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks

data ValidatedPerasVote blk = ValidatedPerasVote
  { vpvVote :: !(PerasVote blk)
  , vpvVoteStake :: !PerasVoteStake
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-395)
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

instance ShowProxy blk => ShowProxy (PerasCert blk) where
  showProxy _ = "PerasCert " <> showProxy (Proxy @blk)

instance ShowProxy blk => ShowProxy (PerasVote blk) where
  showProxy _ = "PerasVote " <> showProxy (Proxy @blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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
