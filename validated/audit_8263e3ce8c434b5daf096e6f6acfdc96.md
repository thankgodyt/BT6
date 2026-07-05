### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Unauthenticated Peras Certificates, Corrupting Chain Selection Weight - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides a `validatePerasCert` implementation that unconditionally accepts every inbound certificate without performing any cryptographic or structural check. Because the Peras certificate diffusion mini-protocol feeds received certificates directly through this function before adding them to the `PerasCertDB` and triggering chain selection, any unprivileged peer can inject a certificate that boosts an arbitrary block by `perasWeight = 15` units of chain-selection weight, potentially causing an honest node to prefer a non-canonical fork.

---

### Finding Description

The default `BlockSupportsPeras` instance (applied to every block type via `instance StandardHash blk => BlockSupportsPeras blk`) implements `validatePerasCert` as a stub that always returns `Right`:

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

No signature, quorum, round-number range, boosted-block existence, or any other property of the certificate is checked. The `PerasValidationErr` data type is itself a single-constructor stub with no fields, making it structurally impossible to express any real error. [2](#0-1) 

The inbound certificate processing path in `makePerasCertPoolWriterFromChainDB` calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` then adds every certificate that passes this non-validation to the `PerasCertDB` via `addPerasCertAsync`: [4](#0-3) 

Once stored, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from every certificate in the DB, mapping each boosted block's `Point` to its `PerasWeight`: [5](#0-4) 

Chain selection then consumes this snapshot in `preferAnchoredCandidate` and `compareAnchoredFragments`. When the snapshot is non-empty, the comparison switches from pure block-number ordering to weighted ordering:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (..., oursSuffix, candSuffix) ->
        compare
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix)
``` [6](#0-5) 

`wsvTotalWeight` is `BlockNo + PerasWeight`, so a fork whose tip block carries an injected boost of `PerasWeight 15` appears 15 block-lengths heavier than it actually is: [7](#0-6) 

The default `perasWeight` is `PerasWeight 15`: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer that sends a single crafted `PerasCert` naming any block on a minority fork causes the receiving node to add `PerasWeight 15` to that fork's chain-selection score. Because `wsvTotalWeight = BlockNo + PerasWeight`, a fork that is up to 15 blocks shorter than the canonical chain will appear equally or more preferable. The node will then switch to the non-canonical fork, constituting a chain-selection safety failure. This maps to:

- **Critical**: Bypass of Peras certificate validation enabling unauthorized certificate acceptance.
- **High**: Chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol and its `ObjectPoolWriter` wiring are fully implemented in production files. Any peer that can establish a connection and speak the Peras cert mini-protocol can trigger this path. The only prerequisite is that Peras is enabled on the target network (controlled by `eraPerasRoundLength`). The stub is explicitly marked as a TODO pending real validation, confirming the missing check is known but not yet guarded.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate signature against the claimed voter set and the boosted block.
2. That the round number is within the valid window (`perasCertMaxRounds`).
3. That the boosted block exists and is within the volatile suffix (not older than the immutable tip).
4. That the quorum threshold was met by the signers.

Until real validation is in place, the `processCerts` inbound path should reject all externally received certificates (return an error unconditionally) rather than accept them all.

---

### Proof of Concept

**Entry path** (production code, no test infrastructure required):

1. Attacker connects to a node and speaks the Peras certificate object-diffusion mini-protocol.
2. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = <point on minority fork> }`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`. [9](#0-8) 
4. Certificate is stored in `PerasCertDB`; `implGetWeightSnapshot` now returns a non-empty snapshot with `PerasWeight 15` on the minority-fork block. [10](#0-9) 
5. `chainSelSync` triggers chain selection for the boosted block via `chainSelectionForBlock`. [11](#0-10) 
6. `preferAnchoredCandidate` now uses weighted comparison; the minority fork with `PerasWeight 15` boost beats the canonical chain if it is within 15 blocks of the canonical tip. [12](#0-11) 
7. Node switches to the non-canonical fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
