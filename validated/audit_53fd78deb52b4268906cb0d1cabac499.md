### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates, Enabling Arbitrary Chain-Selection Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance ships a deliberately incomplete (stub) `validatePerasCert` implementation that returns `Right` for every certificate it receives, performing zero cryptographic or semantic checks. Because this function is wired directly into the live certificate-ingestion pipeline (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block's chain-selection weight, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Vulnerability class (analog mapping):** The external report describes a two-phase operation where the first phase (`RequestDeposit`) performs no bounds/range validation on a user-supplied parameter, while the second phase (`ExecuteDeposit`) has a validation gate whose controlling parameter is itself unbounded. The analog here is structurally identical: the first phase (`validatePerasCert`) performs no validation at all on the peer-supplied certificate, and the second phase (chain selection via `chainSelSync`) applies the boost weight from `perasWeight params` without any re-validation of the certificate's authenticity or correctness.

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` instance is explicitly labelled a "degenerate instance for all blks to get things to compile" and its `validatePerasCert` implementation unconditionally returns `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- boost assigned with no cert check
      }
``` [1](#0-0) 

No signature verification, no round-number range check, no boosted-block existence or ancestry check, and no quorum-proof check is performed. The `vpcCertBoost` is assigned directly from `perasWeight params` regardless of what the certificate actually attests.

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

This stub is called unconditionally in the live certificate pool writer:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

Every inbound `PerasCert` from a peer passes through `processCerts`, which calls this validator. Because the validator always returns `Right`, every certificate is timestamped and forwarded to `addPerasCertAsync`.

**Chain-selection consequence — `chainSelSync`:**

Once a certificate clears the (non-existent) validation gate, `chainSelSync` triggers a full chain-selection pass for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [3](#0-2) 

The `WeightedSelectView` comparator adds `wsvWeightBoost` (sourced from the certificate's `vpcCertBoost`) to the chain's total weight, so a chain containing the boosted block can overtake the current selection purely on the strength of the injected boost. [4](#0-3) 

**Secondary unbounded-parameter analog:**

The `stakeAboveThreshold` function carries an explicit TODO noting that `PerasVoteStake` and the quorum threshold in `PerasParams` are assumed to be in the same units with no enforcement:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units.
``` [5](#0-4) 

This mirrors the external report's second sub-issue: the controlling parameter (`perasWeight`, quorum threshold) has no enforced bounds, so even if real validation were added, the threshold comparison could be incorrect.

---

### Impact Explanation

An unprivileged peer connected via the object-diffusion mini-protocol can craft a `PerasCert` pointing to any block in the VolatileDB. Because `validatePerasCert` accepts it unconditionally, the certificate is stored and the boosted block undergoes chain selection with an artificially inflated weight. If the boost exceeds the weight difference between the honest chain and a competing fork, the node switches to the fork. This constitutes a **chain-selection safety failure**: an honest node is made to prefer a non-canonical or adversarially-constructed chain without any stake-majority requirement, violating the Peras security assumption that only quorum-certified blocks receive a weight boost.

---

### Likelihood Explanation

The object-diffusion protocol for Peras certificates is reachable by any peer the node accepts connections from. No special key material, stake, or operator access is required. The attack path is a single crafted `PerasCert` message. The stub is present in the current production codebase and is wired into the live `ChainDB` pipeline; the linked GitHub issue (`cardano-peras/issues/120`) confirms the gap is known but unresolved.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras object-diffusion pipeline is enabled on any network. At minimum this must include: aggregate-signature verification over the claimed voter set, round-number range checks (cert round must be within the current or recent Peras window), and verification that the boosted block is a known, header-validated block on a plausible chain.
2. **Gate the pipeline on Peras being enabled** (`eraPerasRoundLength /= NoPerasEnabled`) so that nodes on eras where Peras is inactive cannot be reached by this path at all.
3. **Enforce unit consistency** in `stakeAboveThreshold` by normalising `PerasVoteStake` to the same relative scale as `perasQuorumStakeThreshold` before comparison, or by making the type system enforce the invariant.

---

### Proof of Concept

1. Connect to a target node via the Peras object-diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on a competing fork>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
4. `addPerasCertAsync` enqueues the certificate; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
5. `weightBoostOfFragment` adds `vpcCertBoost` to the fork's total weight; if the boost exceeds the honest chain's lead, `preferCandidate` returns `ShouldSwitch` and the node rolls back to the adversarial fork. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
