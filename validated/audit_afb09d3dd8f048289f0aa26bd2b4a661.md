### Title
Unconditional Peras Certificate Acceptance Enables Adversarial Chain Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. This instance is wired into the production `makePerasCertPoolWriterFromChainDB` path. An unprivileged peer can inject an arbitrary crafted `PerasCert` that boosts any block by `PerasWeight 15`, causing an honest node's chain selection to prefer a non-canonical adversarial chain over the honest chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must reject invalid Peras certificates before they enter the weight snapshot used for chain selection. The degenerate instance, explicitly marked as a placeholder for all block types, implements this gate as a no-op:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
``` [1](#0-0) 

This instance is used directly in the production certificate ingest path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, since `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

The accepted certificate is stored in `PerasCertDB`. `implGetWeightSnapshot` then builds a `PerasWeightSnapshot` from all stored certificates:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds)
  ]
``` [4](#0-3) 

This snapshot is consumed by `preferAnchoredCandidate` and `compareAnchoredFragments` during chain selection. When Peras is active (non-empty snapshot), the comparison uses `weightedSelectView`, which computes `wsvTotalWeight = BlockNo + wsvWeightBoost`: [5](#0-4) [6](#0-5) 

The analog to the vault vulnerability is exact: just as the vault treated 1M DAI and 1M USDT as identical shares regardless of their real value, `validatePerasCert` treats a fraudulent certificate and a legitimate one as identical, assigning the same `PerasWeight 15` boost to any block the attacker names.

---

### Impact Explanation

An adversary who injects a `PerasCert` naming block `B` on their fork causes `B` to receive `PerasWeight 15` in the honest node's weight snapshot. Chain selection then computes the adversarial fragment's total weight as `BlockNo(tip) + 15`. A fork that is up to 15 blocks shorter than the honest chain will be preferred if it carries this fraudulent boost. This constitutes a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain, violating the Peras security assumption that only legitimately certified blocks receive weight boosts.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is reachable by any peer that connects to the node. No stake, key material, or privileged access is required. The attacker only needs to craft a `PerasCert` with a `pcCertRound` not already in the DB and a `pcCertBoostedBlock` pointing to a block on their fork. The `processCerts` deduplication check only filters by `PerasRoundNo`; it does not prevent a new round number from being used. The attack is therefore trivially executable by any unprivileged network peer once the Peras ObjectDiffusion protocol is active.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the known committee public keys for that round.
2. That the committee membership bitmap (`pcVoters`) represents a quorum of eligible voters for the round.
3. That `pcCertBoostedBlock` refers to a block that is on a known chain and satisfies the `PerasBlockMinSlots` age requirement.

Until the real validation is implemented, the production `makePerasCertPoolWriterFromChainDB` path should not be activated, or inbound certificates should be dropped entirely rather than accepted unconditionally.

The existing `PerasCert.V1` module already defines the concrete BLS-based certificate structure with `pcSignature` and `pcVoters` fields that the real validation should use: [7](#0-6) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects via the ObjectDiffusion mini-protocol for Peras certificates.
2. Peer sends a batch containing one crafted certificate:
   ```
   PerasCert { pcCertRound = <fresh round number>,
               pcCertBoostedBlock = <point on adversarial fork> }
   ```
3. `processCerts` filters out already-known rounds (none match), then calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally. [8](#0-7) 
5. The cert is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. On the next chain selection event, `getPerasWeightSnapshot` returns a snapshot containing the adversarial block with `PerasWeight 15`.
7. `preferAnchoredCandidate` computes the adversarial fragment's total weight as `BlockNo(adversarial tip) + 15`.
8. If the adversarial chain is within 15 blocks of the honest tip, `ShouldSwitch` is returned and the node adopts the adversarial chain. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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
