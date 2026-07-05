### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Arbitrary Chain-Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as a stub that unconditionally returns `Right` for every input certificate, performing zero cryptographic or semantic checks. This stub is wired directly into the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB` → `processCerts`). An unprivileged peer can therefore send a crafted `PerasCert` that boosts any arbitrary block point, causing the `PerasWeightSnapshot` used in chain selection to be permanently polluted, and potentially causing the node to prefer a non-canonical adversarial chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The catch-all `BlockSupportsPeras` instance covers every block type (including the production Cardano block):

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

Every certificate, regardless of its content, is wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost (currently `PerasWeight 15` from `mkPerasParams`).

**Production inbound path — `processCerts`:**

`makePerasCertPoolWriterFromChainDB` is the production writer used by the Peras certificate object-diffusion mini-protocol. It calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

Inside `processCerts`, any certificate that passes `validateCert` (which always returns `Right`) is immediately forwarded to `addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [3](#0-2) 

**Weight snapshot pollution — `implGetWeightSnapshot`:**

Once stored in `PerasCertDB`, the certificate's `(boostedBlock, boost)` pair is included in every subsequent `PerasWeightSnapshot` computation:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
``` [4](#0-3) 

**Chain selection uses the polluted snapshot:**

`chainSelection` receives the `PerasWeightSnapshot` via `ChainSelEnv.weights` and passes it to `preferAnchoredCandidate` / `compareAnchoredFragments`. When Peras weights are non-empty, chain comparison switches from block-number comparison to `weightedSelectView`, where `wsvTotalWeight = PerasWeight(blockNo) + weightBoost`:

```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert (all (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst) chainDiffs)
  ...
``` [5](#0-4) 

A fake boost of `PerasWeight 15` means a chain 15 blocks shorter than the honest tip can be preferred.

---

### Impact Explanation

This is a **Critical** bypass of Peras certificate validation. An unprivileged peer can send a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork. Because `validatePerasCert` never rejects any certificate, the adversarial block receives a weight boost of 15 in the node's `PerasWeightSnapshot`. Chain selection then uses this polluted snapshot, and the adversarial chain is preferred over the honest chain whenever the honest chain's block-number lead is less than 15. This constitutes unauthorized certificate acceptance and a chain-selection safety failure.

---

### Likelihood Explanation

Any peer connected via the Peras certificate object-diffusion mini-protocol can trigger this path. No stake, keys, or committee membership is required — only network connectivity. The `processCerts` function is the sole gatekeeper, and its validator (`validatePerasCert mkPerasParams`) always returns `Right`. The attack is deterministic and requires sending a single well-formed (but semantically invalid) `PerasCert` message.

---

### Recommendation

Replace the stub `validatePerasCert` with a concrete implementation that performs:
1. **Committee membership check** — verify the voters are eligible for the claimed round.
2. **Cryptographic signature verification** — verify the aggregate BLS signature over `(roundNo, boostedBlock)`.
3. **Round number validity** — reject certificates for rounds too far in the past or future.
4. **Boosted block existence and ancestry check** — verify the boosted block is on a known chain.

The existing BLS infrastructure in `Ouroboros.Consensus.Peras.Crypto.BLS` and the `WFALS`/`EveryoneVotes` committee implementations already provide the necessary primitives. This is tracked upstream at https://github.com/tweag/cardano-peras/issues/120.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = <block point on adversarial fork>`.
3. Send the certificate to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → unconditionally returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
5. `addPerasCertAsync` enqueues the certificate; `implAddCert` stores it in `PerasCertDB`.
6. `implGetWeightSnapshot` now includes `(adversarialBlockPoint, PerasWeight 15)` in the snapshot.
7. The next `chainSelSync` call reads the snapshot via `mkChainSelEnv` and passes it to `chainSelection`.
8. `preferAnchoredCandidate` switches to `weightedSelectView`; the adversarial chain's total weight exceeds the honest chain's if the honest chain leads by fewer than 15 blocks.
9. The node switches to the adversarial chain. [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1144)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
 where
  ChainSelEnv{..} = chainSelEnv

  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L61-68)
```haskell
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
