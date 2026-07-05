### Title
Peras Certificate Validation is an Unconditional No-Op Stub, Enabling Arbitrary Chain Weight Injection via Crafted Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. This is the only instance wired into the production object-diffusion inbound path. An unprivileged peer can therefore send a crafted `PerasCert` that claims to boost any block with any weight, bypassing all validation, and cause the receiving node to add artificial Peras weight to that block's chain. Chain selection then uses this inflated weight to decide whether to switch forks, potentially making the node abandon its current chain in favour of an attacker-controlled one.

This is the direct consensus analog of the LybraFinance finding: just as `rigidRedemption` lacked the timelock that `withdraw` enforced—allowing a user to bypass the intended protection and extract value—`validatePerasCert` lacks the cryptographic checks that the `BlockSupportsPeras` interface promises, allowing a peer to bypass certificate authentication and inject arbitrary chain weight.

---

### Finding Description

**Root cause — `validatePerasCert` always succeeds:** [1](#0-0) 

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

This is the catch-all instance (`instance StandardHash blk => BlockSupportsPeras blk`) and is the only instance in the codebase. Every certificate, regardless of its cryptographic content, is accepted and assigned the full configured `perasWeight`.

**Inbound path — production object-diffusion wires this stub directly:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validator. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would throw `PerasCertInboundException` and disconnect the peer is never reached. [3](#0-2) 

**Storage — `implAddCert` also carries a TODO for non-trivial validation:** [4](#0-3) 

The comment `-- TODO: we will need to update this method with non-trivial validation logic` confirms that the current implementation is intentionally incomplete, but it is wired into the live chain-selection path.

**Chain selection — injected weight directly influences fork choice:**

Once a certificate is stored, `chainSelSync` for `ChainSelAddPerasCert` reads the boosted block from the VolatileDB and calls `chainSelectionForBlock`: [5](#0-4) 

Chain selection then computes `wsvTotalWeight = BlockNo + weightBoost` for each candidate: [6](#0-5) 

A candidate chain whose tip block has a lower `BlockNo` than the current chain can be preferred if its `weightBoost` is large enough. The attacker controls both the boosted block point and the boost magnitude (via `perasWeight params`, which is a fixed placeholder value applied to every accepted certificate).

**`rollbackExceedsSuffix` pre-filter also uses the injected weight:** [7](#0-6) 

Candidates are pre-filtered using `totalWeightOfFragment`, so an attacker-boosted fork that would otherwise be discarded as "too short" can survive the filter and proceed to full validation and adoption.

---

### Impact Explanation

An unprivileged peer can:

1. Send a `PerasCert` claiming to boost a block on a competing (shorter) fork.
2. The receiving node accepts it without any cryptographic check.
3. The `PerasWeightSnapshot` is updated with the artificial boost.
4. Chain selection re-evaluates the boosted block's chain and may find it heavier than the current selection.
5. The node rolls back its current chain and adopts the attacker's fork.

This is a **chain-selection safety failure**: an honest node can be made to prefer a non-canonical, attacker-controlled chain purely through crafted network messages, with no stake, VRF key, or KES key required. The Peras weight boost is designed to accelerate settlement finality; subverting it inverts that property, making settlement *less* secure.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is wired into the production `ChainDB` API (`addPerasCertAsync`) and is reachable from any connected peer. No special privileges are required. The attacker only needs to know the hash of a block in the target node's VolatileDB (obtainable via the ChainSync protocol) to craft a certificate that boosts it. The attack is deterministic and requires no brute force.

---

### Recommendation

1. **Implement real `validatePerasCert`**: The function must verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the committee's public keys, check that the signers form a valid quorum, and verify VRF eligibility proofs. The `PerasCert.V1` module already defines the concrete certificate structure with `pcSignature` and `pcVoters` fields for this purpose. [8](#0-7) 

2. **Remove the catch-all stub instance**: The `instance StandardHash blk => BlockSupportsPeras blk` that always returns `Right` must not be reachable from any production code path. Each concrete block type must provide its own validated instance.

3. **Add a guard in `implAddCert`**: The `PerasCertDB` should not accept a `ValidatedPerasCert` whose `vpcCert` has not been verified against the current epoch's committee. The TODO at line 167 of `PerasCertDB/Impl.hs` must be resolved before Peras is enabled on any network.

---

### Proof of Concept

```
Attacker (peer) → sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <fork tip> }
  ↓
processCerts calls validatePerasCert mkPerasParams
  → always returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })
  ↓
addPerasCertAsync → ChainSelAddPerasCert enqueued
  ↓
chainSelSync: boostedBlock found in VolatileDB
  → chainSelectionForBlock triggered for fork tip
  ↓
constructPreferableCandidates: fork fragment has
  wsvTotalWeight = BlockNo(fork_tip) + perasWeight
  > wsvTotalWeight = BlockNo(current_tip) + 0
  → ShouldSwitch
  ↓
Node rolls back current chain, adopts attacker's fork
```

The attacker needs only a valid peer connection and knowledge of a block hash in the target's VolatileDB. No cryptographic material is required.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-531)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Fragment/Diff.hs (L74-98)
```haskell
-- | Return 'True' iff applying the 'ChainDiff' to the given chain @C@ will
-- result in a chain with less weight than @C@, i.e., the suffix of @C@ to roll
-- back has more weight than suffix is adding.
rollbackExceedsSuffix ::
  forall b0 b1 b2.
  ( HasHeader b0
  , HasHeader b1
  , HasHeader b2
  , HeaderHash b0 ~ HeaderHash b1
  , HeaderHash b0 ~ HeaderHash b2
  ) =>
  PerasWeightSnapshot b0 ->
  -- | The chain @C@ the diff is applied to.
  AnchoredFragment b1 ->
  ChainDiff b2 ->
  Bool
rollbackExceedsSuffix weights curChain (ChainDiff nbRollback suffix) =
  weightOf suffixToRollBack > weightOf suffix
 where
  suffixToRollBack = AF.anchorNewest nbRollback curChain

  weightOf ::
    (HasHeader b, HeaderHash b ~ HeaderHash b0) =>
    AnchoredFragment b -> PerasWeight
  weightOf = totalWeightOfFragment weights
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-60)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
```
