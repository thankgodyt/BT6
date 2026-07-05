### Title
`validatePerasCert` Stub Always Accepts Any Certificate, Enabling Unauthorized Peras Weight Boost Injection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. Because this function is wired directly into the live `ObjectDiffusion` inbound pipeline (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject an arbitrary `PerasCert` that is accepted, stored in the `PerasCertDB`, and used to boost a block's weight in chain selection. When Peras is enabled, this lets an attacker make an honest node prefer a shorter adversarial chain over the honest chain.

---

### Finding Description

**Root cause — the stub that never rejects:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

This is the only `BlockSupportsPeras` instance in the codebase (the comment at line 318 calls it a "degenerate instance for all blks to get things to compile"). No Cardano-specific override exists. Every `PerasCert` received from any peer is unconditionally wrapped in `ValidatedPerasCert` and assigned the full configured Peras weight boost.

**Entry path — the inbound ObjectDiffusion pipeline:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`. Because `validatePerasCert` always returns `Right`, `processCerts` never reaches the rejection branch: [3](#0-2) 

Every cert in the batch is accepted and forwarded to `ChainDB.addPerasCertAsync`.

**Chain selection consequence:**

Once a cert is stored in the `PerasCertDB`, `chainSelSync` triggers chain selection for the boosted block: [4](#0-3) 

Chain selection now uses `WeightedSelectView`, where `wsvTotalWeight = blockNo + wsvWeightBoost`. A chain containing the attacker-boosted block is preferred over a longer honest chain if the injected boost is large enough: [5](#0-4) 

**The analog to the external report:**

In the Paraspace bug, `removeFeeder()` uses `onlyWhenFeederExisted` — a guard that checks existence but not caller identity, so anyone can call it. Here, `validatePerasCert` is a guard that checks nothing at all: it is named and typed as a validation function, it is called in the validation slot of `processCerts`, but it unconditionally approves every input. The "check" does not check.

---

### Impact Explanation

**Severity: High — Chain selection bug enabling unauthorized chain preference manipulation.**

When Peras is enabled, an unprivileged peer connected via the ObjectDiffusion mini-protocol can:

1. Craft a `PerasCert` pointing to any block hash (e.g., a block on a shorter adversarial fork).
2. Send it to the victim node; `validatePerasCert` accepts it unconditionally.
3. The cert is stored and triggers chain selection with the full configured Peras weight boost applied to the adversarial block.
4. If the boost exceeds the honest chain's length advantage, the node switches to the adversarial chain — a chain selection safety failure.

This matches the allowed impact scope: *"High — Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is reachable by any connected peer without any privilege. The attacker needs only to send a well-formed CBOR-encoded `PerasCert` with a `pcCertBoostedBlock` pointing to a block on a fork they control. No key material, stake, or operator access is required. The attack is repeatable: the only deduplication is by `PerasRoundNo`, so the attacker can use a fresh round number each time. The condition is that Peras must be enabled on the target node, which is the intended production configuration for future Cardano eras.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The aggregate BLS signature over `(electionId, candidate)` using the committee's aggregate verification key.
- That the claimed voters form a valid quorum (sufficient stake).
- That each voter's VRF output (for non-persistent members) is valid.
- That the `pcCertRound` and `pcBoostedBlock` are within acceptable bounds relative to the current ledger state.

Until a real implementation is available, the inbound `processCerts` pipeline should refuse all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them. The existing `implVerifyCert` in `WFALS.hs` demonstrates the correct structure for full certificate verification. [6](#0-5) 

---

### Proof of Concept

**Attacker-controlled entry path (no privileges required):**

1. Connect to a Peras-enabled Cardano node as a normal peer via the ObjectDiffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of a block on an adversarial fork (shorter than the honest chain by up to `perasWeight` blocks)
3. Send the cert batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}`.
5. The cert is added to `PerasCertDB`; `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
6. `weightedSelectView` computes `wsvTotalWeight = blockNo(adversarial tip) + perasWeight` which now exceeds `blockNo(honest tip) + 0`.
7. `preferCandidate` returns `ShouldSwitch`; the node rolls back to the adversarial chain. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-494)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```
