### Title
Unconditional `validatePerasCert` Acceptance Enables Crafted-Certificate Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally accepts every inbound `PerasCert` without performing any cryptographic or semantic validation. An unprivileged peer can send a crafted certificate whose `pcCertBoostedBlock` points to a block on an adversarial fork. Because the certificate is accepted and stored, chain selection awards that fork a `PerasWeight 15` boost, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a certificate before it influences chain selection. The only concrete instance in the codebase is a universal degenerate instance that applies to **all** block types:

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

This function always returns `Right`, regardless of the certificate's content. There is no more specific instance for Cardano block types; this degenerate instance is the only one.

The production inbound-certificate handler `processCerts`, called from `makePerasCertPoolWriterFromChainDB`, passes this stub directly as the validation function:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` applies `validateCert` to every certificate received from a peer; if all pass (which they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Once stored, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` directly from every certificate's `getPerasCertBoostedBlock` / `getPerasCertBoost` pair: [4](#0-3) 

That snapshot is consumed by `weightBoostOfFragment` during chain selection: [5](#0-4) 

`preferCandidate` then compares `wsvTotalWeight` (block number + weight boost) between the current chain and candidates: [6](#0-5) 

The default `perasWeight` is `PerasWeight 15`, meaning a single accepted certificate adds 15 to a chain fragment's total weight — equivalent to 15 extra blocks. [7](#0-6) 

---

### Impact Explanation

**High.** An unprivileged peer can send a `PerasCert` whose `pcCertBoostedBlock` is a block on an adversarial fork. Because `validatePerasCert` never rejects anything, the certificate is stored and the adversarial block receives a +15 weight boost. If the adversarial fork's tip is within 15 blocks of the honest chain's tip, `preferCandidate` will return `ShouldSwitch` and the node will adopt the adversarial chain. This is a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

**High.** Any peer connected to a Peras-enabled node can send arbitrary `PerasCert` objects over the Peras certificate diffusion mini-protocol. No stake, key material, or special privilege is required. The attack requires only constructing a `PerasCert` CBOR payload with a chosen `pcCertBoostedBlock` and sending it to the target node.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before Peras is enabled in production. At minimum, verify the aggregate BLS signature over the claimed voters and election ID, verify each voter's committee eligibility and VRF output (for non-persistent members), and check that the total stake of the signers exceeds the quorum threshold. The `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert` functions in the `Committee` subsystem already implement this logic for the abstract committee layer and should be wired into the concrete `BlockSupportsPeras` instance.

2. **Remove or gate the degenerate universal instance.** The `instance StandardHash blk => BlockSupportsPeras blk` should not exist in production code. Replace it with a compile-time error or a `Void`-returning stub that cannot be reached at runtime, forcing each concrete block type to supply a real implementation before Peras can be enabled.

3. **Add a feature-flag guard** in `processCerts` / `makePerasCertPoolWriterFromChainDB` that refuses to process inbound certificates if the `validatePerasCert` implementation is the stub, so that enabling Peras without a real validator is a hard error rather than a silent security hole.

---

### Proof of Concept

**Setup:** A private testnet with Peras enabled. Two nodes: an honest node `H` and an adversarial peer `A`.

1. `A` observes that the honest chain's tip is at block `B_honest` (block number `N`).
2. `A` has a competing fork whose tip is at block `B_adv` (block number `N - 14`, i.e., 14 blocks shorter).
3. `A` constructs a CBOR-encoded `PerasCert` with:
   - `pcCertRound` = any round number not yet in `H`'s `PerasCertDB`
   - `pcCertBoostedBlock` = the point of `B_adv`
4. `A` sends this certificate to `H` via the Peras certificate diffusion mini-protocol.
5. `H` calls `processCerts` → `validatePerasCert mkPerasParams` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
6. The certificate is stored; `implGetWeightSnapshot` now maps `B_adv`'s point to `PerasWeight 15`.
7. `H` receives `B_adv` (or already has it in the VolatileDB). `chainSelectionForBlock` is triggered.
8. `weightBoostOfFragment` gives the adversarial fragment total weight `(N - 14) + 15 = N + 1`, which exceeds the honest chain's weight `N`.
9. `preferCandidate` returns `ShouldSwitch`; `H` adopts the adversarial chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
