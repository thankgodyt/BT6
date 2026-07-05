### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that always returns `Right` (valid) for every certificate, regardless of content. Because this is the only instance in the codebase, any unprivileged peer can inject crafted Peras certificates that are accepted without any cryptographic or semantic check. Accepted certificates are stored in the `PerasCertDB`, their boosted-block weight is added to the `PerasWeightSnapshot`, and chain selection is immediately re-triggered — allowing an attacker to artificially inflate the Peras weight of an adversarial chain and cause honest nodes to prefer it over the canonical chain.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the gate that must be passed before a certificate is stored or acted upon: [1](#0-0) 

The only concrete instance in the repository is a universal stub: [2](#0-1) 

`validatePerasCert` unconditionally constructs a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params` and returns `Right`, performing zero cryptographic or semantic checks.

The inbound certificate pipeline in `processCerts` calls this function on every peer-supplied certificate: [3](#0-2) 

Because `validatePerasCert` always succeeds, every certificate passes the `partitionEithers` check and is forwarded to `addCert`. The production writer path uses this same stub: [4](#0-3) 

Once stored, `implAddCert` inserts the certificate into `pcdsCertsByTicket`: [5](#0-4) 

`implGetWeightSnapshot` then recomputes the `PerasWeightSnapshot` from every stored certificate, accumulating `getPerasCertBoost` for each boosted block: [6](#0-5) 

`addToPerasWeightSnapshot` accumulates weight additively for the same point: [7](#0-6) 

Chain selection then uses `wsvTotalWeight` — block number plus accumulated weight boost — to prefer candidates: [8](#0-7) 

When a certificate arrives, `chainSelSync` immediately re-triggers chain selection for the boosted block: [9](#0-8) 

The deduplication guard in `implAddCert` only rejects a second certificate for the **same round number**. An attacker can use a distinct `pcCertRound` for each crafted certificate, bypassing deduplication entirely and accumulating unbounded weight on any target block.

---

### Impact Explanation

An unprivileged peer can send a stream of crafted `PerasCert` messages, each with a unique `pcCertRound` and `pcCertBoostedBlock` pointing to a block on an adversarial fork. Because `validatePerasCert` never rejects any certificate:

1. Each certificate is stored in `PerasCertDB`.
2. The `PerasWeightSnapshot` accumulates `perasWeight params` for the adversarial block on every insertion.
3. Chain selection compares `wsvTotalWeight` (block number + accumulated boost) and switches to the adversarial chain once its total weight exceeds the honest chain's.
4. The honest node permanently adopts the adversarial chain, constituting a consensus safety failure.

This matches the allowed impact scope: **bypass of Peras certificate validation that enables unauthorized certificate acceptance and causes an honest node to prefer a non-canonical chain**.

---

### Likelihood Explanation

- **Prerequisite**: Peras must be enabled. The CHANGELOG notes it is disabled by default, but the code path is fully wired and the stub is the only instance.
- **Attacker capability**: Any peer with a network connection; no keys, stake, or privileged access required.
- **Effort**: Trivial — craft a `PerasCert` with an arbitrary round number and target point and send it via the Peras cert miniprotocol.
- **Detection**: None at the consensus layer; the stub emits no warning.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed committee members.
2. Verifies each voter's committee eligibility and seat index using the stake distribution and VRF output.
3. Verifies the round number falls within the expected window relative to the current chain tip.
4. Verifies the boosted block exists and is a valid chain point.

Until a real implementation is available, the node should refuse to process inbound certificates when Peras is enabled rather than silently accepting all of them.

---

### Proof of Concept

```
1. Enable Peras on a private testnet node.
2. Connect an adversarial peer.
3. Adversarial peer sends N PerasCert messages:
     { pcCertRound = i, pcCertBoostedBlock = <adversarial fork tip> }
   for i = 1 .. N, each with a distinct round number.
4. Each certificate passes validatePerasCert (always Right).
5. implAddCert stores each certificate (distinct roundNo bypasses deduplication).
6. implGetWeightSnapshot accumulates N * perasWeight for the adversarial block.
7. wsvTotalWeight of the adversarial chain = blockNo + N * perasWeight.
8. Once this exceeds the honest chain's total weight, chainSelection switches.
9. The honest node adopts the adversarial chain.
``` [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-298)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
