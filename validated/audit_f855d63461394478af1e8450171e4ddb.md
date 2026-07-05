### Title
Peras Certificate Temporal Validation Bypass Enables Unauthorized Chain Selection Influence - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance unconditionally returns `Right` (success) for every inbound Peras certificate, performing zero validation. Critically, the method's type signature structurally excludes the current Peras round number, making temporal validation — checking whether a certificate's round falls within a valid window — architecturally impossible even if the stub were partially replaced. An unprivileged peer can send a `PerasCert` with any arbitrary round number, have it accepted and stored in the `PerasCertDB`, and trigger chain selection for any block in the volatile DB.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` with the signature:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
``` [1](#0-0) 

The universal instance for all block types implements this as an unconditional stub:

```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [2](#0-1) 

This is the only instance — there is no more specific Cardano override. The `processCerts` function, which handles all inbound peer certificates from the object diffusion miniprotocol, calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

The `processCerts` function receives `SystemTime` (wall-clock time) but **not** the current Peras round number. The `validateCert` callback type is `PerasCert blk -> Either ...`, with no round-number parameter: [4](#0-3) 

After passing the no-op validation, the cert is stored and `chainSelSync` is invoked. The only temporal guard in `chainSelSync` is a slot-based check on the **boosted block** (not the cert's round number):

```haskell
when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
  idExitEarly PerasCertIgnoredTooOld
``` [5](#0-4) 

A cert boosting any block still in the volatile DB — regardless of how far in the future or past its `pcCertRound` is — passes this guard and triggers `chainSelectionForBlock`: [6](#0-5) 

The cert is also stored as `pcdsLatestCertSeen` in the `PerasCertDB` if it has the highest round number seen, which directly feeds the Peras voting rules (VR-1A, VR-2A): [7](#0-6) 

---

### Impact Explanation

**Chain selection (High):** An unprivileged peer sends a `PerasCert` with a valid-looking `pcCertBoostedBlock` pointing to a block on a weaker competing fork that is still in the volatile DB. Because `validatePerasCert` always succeeds and `chainSelSync` only rejects certs whose boosted block is before the immutable tip, the cert is stored and `chainSelectionForBlock` is called for the weaker fork's block. The Peras boost weight (`vpcCertBoost`) is added to that fork's chain weight. If the boost is sufficient to exceed the current chain's weight, the honest node switches to the weaker, non-canonical fork — a direct chain selection safety failure caused by an unprivileged peer.

**Voting state corruption (High):** A cert with a far-future round number (e.g., `pcCertRound = maxBound`) becomes `pcdsLatestCertSeen`. VR-1A requires `currRoundNo == certRound + 1` (fails for a future cert), and VR-2A requires `certRound + R <= currRoundNo` (also fails). Both voting paths are blocked, silently preventing the node from ever voting again until the DB is cleared. [8](#0-7) 

---

### Likelihood Explanation

The attack requires only that a peer connect via the object diffusion miniprotocol and send a crafted `PerasCert` message. No stake, keys, or privileged access are needed. The `PerasCert` type is a simple CBOR-serialized structure with a round number and a block point, both fully attacker-controlled. The object diffusion layer is a public-facing miniprotocol reachable by any peer. [9](#0-8) 

---

### Recommendation

1. **Add the current round number as a parameter to `validatePerasCert`** (or pass it through `processCerts`). The function signature must include the current `PerasRoundNo` so that temporal validity — `certRound ∈ [currRound - maxAge, currRound]` — can be enforced.

2. **Implement actual cert validation** in `validatePerasCert`, including: round-number bounds check, aggregate BLS signature verification, quorum threshold check, and boosted-block existence/era check. The existing TODO at issue [#120](https://github.com/tweag/cardano-peras/issues/120) must be resolved before Peras is enabled on any network.

3. **Add a round-number guard in `chainSelSync`** as a defense-in-depth measure, rejecting certs whose round number is outside a configurable staleness window relative to the current round.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the object diffusion miniprotocol.

2. Attacker observes a block B on a weaker competing fork (still in the
   node's volatile DB, slot > immutable tip slot).

3. Attacker crafts:
     PerasCert { pcCertRound = <any value>, pcCertBoostedBlock = point(B) }

4. Attacker sends the cert batch to the node.

5. processCerts calls (validatePerasCert mkPerasParams cert) => Right ...
   (no round-number check, no signature check, always succeeds).

6. chainSelSync receives the cert:
   - pointSlot(B) >= immTip slot  =>  NOT ignored as too old
   - B is not on the current chain  =>  chainSelectionForBlock is called
   - The cert's boost weight is added to B's fork weight.

7. If boost weight tips the balance, the node adopts the weaker fork.

For the voting-freeze variant:
3'. Attacker crafts:
      PerasCert { pcCertRound = maxBound, pcCertBoostedBlock = <any volatile block> }
7'. This cert becomes pcdsLatestCertSeen.
    VR-1A: currRoundNo == maxBound + 1  => False
    VR-2A: maxBound + R <= currRoundNo  => False
    Node never votes again.
``` [10](#0-9) [11](#0-10) [12](#0-11)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L111-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-532)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L139-165)
```haskell
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
```
