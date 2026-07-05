### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Forge Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional `Right`, meaning every inbound Peras certificate is accepted without any cryptographic or structural validation. The production inbound-certificate pipeline (`processCerts` → `addPerasCertAsync` → `chainSelSync`) feeds directly from this stub. An unprivileged peer can send crafted certificates that artificially boost an adversarial fork's weight, causing the victim node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub wired into production:**

The universal instance (comment: *"TODO: degenerate instance for all blks to get things to compile"*) implements `validatePerasCert` as:

```haskell
-- SupportsPeras.hs lines 350-358
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15 (mkPerasParams)
      }
``` [1](#0-0) 

No signature check, no committee membership check, no quorum check, no round-number sanity check — the function unconditionally wraps any input as a `ValidatedPerasCert`.

**Production call site — inbound certificate pipeline:**

`makePerasCertPoolWriterFromChainDB` (the production writer used with the `ChainDB`) passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
-- PerasCert.hs lines 121-133
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    (validatePerasCert mkPerasParams)   -- ← always Right
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [2](#0-1) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on the remainder. Because `validateCert` always returns `Right`, every new-round certificate passes: [3](#0-2) 

The accepted `ValidatedPerasCert` is then handed to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` event.

**Chain selection consequence:**

`chainSelSync` processes the event: it adds the certificate to `PerasCertDB`, then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection uses `preferAnchoredCandidate`, which compares `wsvTotalWeight` — the sum of `BlockNo` and `wsvWeightBoost` (the accumulated Peras boost from `PerasWeightSnapshot`): [5](#0-4) 

Each forged certificate contributes `perasWeight = 15` (from `mkPerasParams`) to the boosted block's chain weight: [6](#0-5) 

**End-to-end exploit path:**

1. Attacker connects as an ordinary peer via the Peras object-diffusion mini-protocol.
2. Attacker crafts `PerasCert` messages with arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on an adversarial fork.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right`.
4. Certificate is stored and `addPerasCertAsync` triggers `chainSelSync`.
5. `chainSelSync` calls `chainSelectionForBlock` for the boosted block.
6. `preferAnchoredCandidate` computes the adversarial fork's `wsvTotalWeight` as `BlockNo + (15 × number_of_forged_certs)`.
7. If the boosted weight exceeds the honest chain's weight, the node switches to the adversarial fork.

The attacker can send one certificate per round number (deduplicated by `Set PerasRoundNo`), so with `N` distinct round numbers they inject `15N` weight units. With `mkPerasParams` defaults (`perasWeight = 15`, `perasCertMaxRounds = 487`), up to 487 distinct round numbers are usable before expiry, yielding a maximum artificial boost of `15 × 487 = 7305` — enough to overcome a fork that is thousands of blocks shorter than the honest chain.

---

### Impact Explanation

**Severity: Critical / High.**

An unprivileged peer can make an honest node permanently prefer a non-canonical chain by injecting forged Peras certificates. This is a bypass of Peras certificate verification (`validatePerasCert`) that enables unauthorized certificate acceptance and a chain-selection error. The node will switch to and follow an adversarial fork, breaking the Common Prefix property of Ouroboros Praos/Peras for that node.

---

### Likelihood Explanation

**High.** The Peras object-diffusion mini-protocol is a standard network-facing entry point reachable by any peer. The stub is the only `BlockSupportsPeras` instance in the codebase (universal instance for all `blk`). The `TODO` comment and linked issue (`cardano-peras/issues/120`) confirm this is known incomplete work that has been wired into the production pipeline. No privilege, key material, or stake is required.

---

### Recommendation

1. **Do not wire `validatePerasCert` into the production inbound pipeline until a real implementation exists.** Gate `makePerasCertPoolWriterFromChainDB` / `makePerasCertPoolWriterFromCertDB` behind a feature flag that is disabled by default, or replace the stub with a function that returns `Left PerasValidationErr` (reject all) until proper validation is implemented.
2. Implement `validatePerasCert` to verify: committee membership, aggregate vote signature, quorum threshold, round-number bounds, and that the boosted block hash is structurally valid.
3. Track the open issue (`cardano-peras/issues/120`) as a security-blocking item before any Peras-enabled deployment.

---

### Proof of Concept

```
Peer → node: ObjectDiffusion message containing [PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial fork tip> }]

processCerts:
  alreadyInDb = {} (first cert for round R)
  certsNotAlreadyInDb = [cert]
  validatePerasCert mkPerasParams cert = Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 15 })
  → addCert (WithArrivalTime now validatedCert)

chainSelSync:
  boostedBlock = <adversarial fork tip>
  PerasCertDB.addCert → AddedPerasCertToDB
  chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment

preferAnchoredCandidate:
  wsvTotalWeight(adversarial) = BlockNo(adversarial) + 15
  wsvTotalWeight(honest)      = BlockNo(honest)
  If BlockNo(adversarial) + 15 > BlockNo(honest) → ShouldSwitch → node adopts adversarial fork
```

Repeat with distinct round numbers R+1, R+2, … to accumulate up to 7305 weight units of artificial boost.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L170-172)
```haskell
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
```
