### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Always Returning `Right` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic, quorum, committee-membership, or round-validity checks. Any unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block pointer; the certificate will be accepted, stored in the `PerasCertDB`, and used to apply Peras weight boosts during chain selection, potentially causing the node to switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must be passed before a certificate is stored or acted upon. The sole production instance is a degenerate placeholder: [1](#0-0) 

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

This stub is wired directly into the inbound certificate processing path used for both the standalone `PerasCertDB` and the production `ChainDB`: [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate; because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would reject invalid certificates is never taken: [3](#0-2) 

Every accepted certificate is then stored via `implAddCert`, which itself carries a companion TODO acknowledging missing validation logic: [4](#0-3) 

Once stored, the certificate:

1. Updates `pcdsLatestCertSeen` — the field that directly gates Peras voting eligibility: [5](#0-4) 

2. Contributes to `getWeightSnapshot`, which is consumed by chain selection to apply Peras weight boosts to the boosted block: [6](#0-5) 

3. Triggers `ChainDB.addPerasCertAsync`, which can cause an immediate chain-selection fork switch if the boosted block is on a candidate chain: [7](#0-6) 

---

### Impact Explanation

**Impact: High — Chain selection and Peras certificate verification bypass.**

An adversary can craft a `PerasCert` pointing to any block on any candidate chain and send it via the object-diffusion mini-protocol. Because `validatePerasCert` never rejects anything, the certificate is stored and its weight boost is applied unconditionally. If the boosted block is on a candidate chain that would otherwise lose chain selection, the artificial boost can flip the outcome, causing the honest node to adopt a non-canonical chain. Additionally, the corrupted `pcdsLatestCertSeen` state can suppress or manipulate the node's own future voting decisions (VR-1A, VR-1B, VR-2A rules all read from this field).

---

### Likelihood Explanation

**Likelihood: High.** The entry path is the standard object-diffusion mini-protocol for Peras certificates, reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to construct a syntactically valid `PerasCert` CBOR message with a chosen `pcCertRound` and `pcCertBoostedBlock`.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that checks:
- Cryptographic signatures from committee members
- That the aggregate stake of signers meets the quorum threshold (`perasQuorumStakeThreshold`)
- That the round number is within an acceptable window relative to the current chain tip
- That the boosted block is a known, valid block on the chain

Until the real implementation is in place, inbound certificates from peers should be rejected at the network boundary (e.g., by returning a hard error in `processCerts` rather than calling the stub), so that the stub cannot be exploited in a live network.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the object-diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point of a block on a competing candidate chain>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. The certificate is stored in `PerasCertDB`; `pcdsLatestCertSeen` is updated; `getWeightSnapshot` now includes the artificial boost.
5. `ChainDB.addPerasCertAsync` triggers chain selection; if the boosted block is on a candidate chain, the node switches to it. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
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
```
