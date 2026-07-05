### Title
Unconditional Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection via Crafted Peras Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` catch-all instance implements `validatePerasCert` as an unconditional stub that always returns `Right` (success) without performing any cryptographic or structural validation. This stub is wired directly into the production certificate ingest path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send a crafted `PerasCert` with an arbitrary boosted block, have it accepted without any verification, and cause the receiving node to trigger chain selection for that block with a full Peras weight boost, potentially making the node prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The `BlockSupportsPeras` instance for all `StandardHash blk` types implements `validatePerasCert` as a stub that always succeeds:

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
``` [1](#0-0) 

This is the only `BlockSupportsPeras` instance in the codebase (the comment explicitly marks it as a degenerate catch-all: `-- TODO: degenerate instance for all blks to get things to compile`). [2](#0-1) 

**Production wiring — stub called in the peer-facing ingest path:**

Both production pool writers pass this stub directly as the validation function for inbound peer certificates:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

**`processCerts` accepts any certificate that passes this stub:**

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

Since `validatePerasCert` always returns `Right`, `partitionEithers` always produces an empty error list, so every inbound certificate is stored and forwarded to chain selection.

**Chain selection consequence:**

Once stored, the certificate triggers `chainSelSync` for the boosted block, which applies `perasWeight = 15` additional weight to that block during chain selection: [6](#0-5) 

The `perasWeight` is set to `PerasWeight 15` in `mkPerasParams`: [7](#0-6) 

**Analog to the reported vulnerability:**

| Original (`AccessToken.sol`) | Analog (Ouroboros Consensus) |
|---|---|
| `recoverSigner()` returns `address(0)` on failure | `validatePerasCert` returns `Right` unconditionally |
| `require(signer == owner())` passes when owner is `address(0)` | `processCerts` accepts all certs when validator always returns `Right` |
| Anyone can acquire an access token | Any peer can inject an arbitrary Peras certificate |

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block as the boosted block and any round number. Because `validatePerasCert` performs no cryptographic verification (no quorum check, no aggregate BLS signature check, no VRF eligibility check), the certificate is unconditionally accepted. The receiving node then applies a `perasWeight = 15` boost to the adversarially chosen block during chain selection. If the adversary targets a block on a minority fork, the honest node may switch to that fork, diverging from the canonical chain. This satisfies the **High** impact category: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attack requires only network connectivity to a running node's Peras certificate diffusion miniprotocol. No stake, no keys, no prior authentication is needed. The peer simply sends a well-formed CBOR-encoded `PerasCert` with a crafted `pcCertBoostedBlock`. The stub is unconditional and has no guards. Likelihood is **High** given the zero-privilege entry path and the fact that the stub is already wired into both the `PerasCertDB`-backed and `ChainDB`-backed production writers.

---

### Recommendation

1. Replace the stub `validatePerasCert` implementation with a real validator that verifies: (a) the aggregate BLS vote signature over the election ID and boosted block, (b) that the declared voters form a valid quorum above `perasQuorumStakeThreshold`, and (c) that each voter's eligibility proof (VRF output for non-persistent members) is valid. The `implVerifyCert` function in `Ouroboros.Consensus.Committee.WFALS` provides the correct reference implementation pattern.
2. Until the real validator is in place, gate the `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` paths behind a feature flag so they are not reachable from untrusted peers on production nodes.
3. Track and close issue `https://github.com/tweag/cardano-peras/issues/120` before any production deployment of the Peras diffusion miniprotocol.

---

### Proof of Concept

1. Connect to a node's Peras certificate diffusion miniprotocol endpoint.
2. Encode and send a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <hash of a block on a minority fork>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = PerasWeight 15}`.
4. The certificate is stored in `PerasCertDB`.
5. `chainSelSync` is invoked for the boosted block; the block now carries 15 additional weight units.
6. If the minority fork's total weight (including the boost) exceeds the current chain's weight, the node switches to the minority fork. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-106)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
