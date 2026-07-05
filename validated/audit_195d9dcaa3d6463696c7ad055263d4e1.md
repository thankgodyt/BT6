### Title
Peras Certificate Validation Is a No-Op Stub — Any Peer Can Inject Arbitrary Certificates That Influence Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines a `validatePerasCert` method intended to authenticate inbound Peras certificates before they are stored and used to boost chain-selection weight. The sole production instance of this method is an unconditional stub that always returns `Right` — it performs zero cryptographic or committee-membership checks. Any unprivileged peer that can reach the Peras certificate ObjectDiffusion mini-protocol can inject a certificate for any block, causing the receiving node to apply a weight boost of `perasWeight = 15` to that block and potentially switch to an adversarially chosen chain.

---

### Finding Description

**Root cause — stub validation that always succeeds**

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
``` [1](#0-0) 

This is the **only** instance of `BlockSupportsPeras` in the codebase (it is a universal `instance StandardHash blk => BlockSupportsPeras blk`). No other instance overrides it. The function ignores every field of the certificate except to copy it into the result, and unconditionally assigns the configured `perasWeight` boost.

**Production call path**

`makePerasCertPoolWriterFromChainDB` — the production-wired writer for the Peras certificate ObjectDiffusion mini-protocol — passes this stub directly as the validation callback:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` treats a `Right` result as a fully validated certificate and immediately forwards it to `addCert`: [3](#0-2) 

`ChainDB.addPerasCertAsync` enqueues the certificate for `chainSelSync`, which adds it to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

**Chain-selection consequence**

`WeightedSelectView` computes `wsvTotalWeight = blockNo + weightBoost`. A boost of 15 means a chain containing the adversarially boosted block is preferred over any honest chain that is up to 15 blocks longer: [5](#0-4) 

The `perasWeight` default is hardcoded to 15 in `mkPerasParams`: [6](#0-5) 

**Analog to the external report**

The `BlockSupportsPeras` class declares `validatePerasCert` as the enforcement point for certificate validity — exactly as `OmoVault` declares `supplyCap` as the enforcement point for deposit limits. In both cases the enforcement variable/method exists and is called, but the actual check is absent: `OmoVault` has the check commented out; `validatePerasCert` has it replaced by an unconditional `Right`.

---

### Impact Explanation

**Severity: Critical** — matches "Bypass of certificate/signature validation that enables unauthorized certificate acceptance."

An unprivileged peer can craft a `PerasCert` naming any block in the receiving node's VolatileDB as the boosted block. The node will:
1. Accept the certificate without any cryptographic verification.
2. Store it in `PerasCertDB` with a weight boost of 15.
3. Re-run chain selection, potentially switching away from the honest chain to a chain containing the adversarially boosted block.

Because the boost is 15 and the security parameter `k = 2160`, a single injected certificate can cause the node to prefer a fork that is up to 15 blocks shorter than the honest chain. An attacker who injects certificates for every round can accumulate boosts that persistently bias chain selection, undermining the Peras settlement guarantee and potentially causing the node to permanently diverge from the honest chain.

---

### Likelihood Explanation

**High.** The ObjectDiffusion mini-protocol for Peras certificates is wired into the production `ChainDB` path. Any peer that can establish a connection and speak the Peras certificate sub-protocol can trigger this path. No privileged keys, stake, or special role is required. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm the stub is intentional but unfinished, meaning it is present in any deployment that enables Peras (including private testnets, which are explicitly in scope).

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that verifies:
1. The certificate carries a valid aggregate signature from a quorum of committee members for the claimed round.
2. The voter IDs and their stakes are drawn from the correct epoch's stake distribution.
3. The boosted block's slot satisfies `perasBlockMinSlots` (minimum age).
4. The certificate round number is within the valid window (`perasCertMaxRounds`).

Until real validation is implemented, the Peras certificate ObjectDiffusion mini-protocol should be disabled or gated behind a feature flag that is off by default, so that the stub cannot be reached from untrusted peers.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to the target node as an unprivileged peer via the Peras certificate ObjectDiffusion mini-protocol.
2. Observe the node's VolatileDB to identify a block `B` on a minority fork (e.g., one that is 10 blocks shorter than the current selection).
3. Send a `PerasCert { pcCertRound = <any fresh round>, pcCertBoostedBlock = point(B) }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = 15 }` unconditionally.
5. `ChainDB.addPerasCertAsync` enqueues the cert; `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for `B`.
6. `WeightedSelectView` now scores the minority fork as `blockNo(B) + 15`, which exceeds the honest tip's `blockNo(honest_tip) + 0` if the fork is fewer than 15 blocks behind.
7. The node switches to the minority fork — a chain-selection manipulation achieved with zero cryptographic material. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
