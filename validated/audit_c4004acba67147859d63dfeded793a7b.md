### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` method is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` over the Peras certificate diffusion miniprotocol; the certificate will be accepted, stored in the `PerasCertDB`, and its `perasWeight` boost (15 slots of chain weight) will be applied to an arbitrary block during chain selection. This allows an adversary to make an honest node prefer a non-canonical chain without holding any stake or keys.

---

### Finding Description

**Root cause — stub validator always succeeds:**

The `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasCert` as:

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

No aggregate BLS signature check, no VRF eligibility proof check, no quorum threshold check, and no round-number/boosted-block consistency check is performed. The `PerasValidationErr` data type is also a stub with a single constructor and no error variants: [2](#0-1) 

**Attacker-controlled entry path:**

Both production pool writers pass this stub as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` receives a peer-supplied list of `PerasCert` values, calls `validateCert` on each, and — because the stub always returns `Right` — immediately adds every certificate to the database: [4](#0-3) 

**Chain selection impact:**

Once stored, the certificate's boost is applied via `implGetWeightSnapshot`, which reads `getPerasCertBoost cert` (= `perasWeight params` = 15) for every stored certificate and adds it to the weight of the boosted block: [5](#0-4) 

`chainSelSync` then triggers `chainSelectionForBlock` for the boosted block, potentially switching the node to a fork that carries the fraudulent certificate's weight: [6](#0-5) 

The correct validation logic — aggregate BLS signature verification, batch VRF output verification, and quorum checks — exists in `implVerifyCert` for the `WFALS` committee scheme and in `implVerifyCert` for `EveryoneVotes`, but neither is wired into the production certificate ingestion path: [7](#0-6) 

---

### Impact Explanation

**High — chain selection bug.** An unprivileged peer can inject a `PerasCert` that names any block hash as the boosted block. The node will apply `perasWeight` (15 slots of chain weight) to that block and may switch to a fork it would otherwise reject. Because Peras weight is additive and persists in the `PerasCertDB`, a single fraudulent certificate permanently biases chain selection for the lifetime of the certificate (up to `perasCertMaxRounds` = 487 rounds). An adversary with no stake and no keys can force an honest node off the canonical chain, violating the Peras safety guarantee that only a quorum-certified block should receive a boost.

---

### Likelihood Explanation

**High.** The Peras certificate diffusion miniprotocol is an externally reachable network endpoint. Any peer that can connect to the node can send a `PerasCert` message. The stub is the only `BlockSupportsPeras` instance in the codebase and is used unconditionally. No privilege, stake, or key material is required. The TODO comment and linked issue confirm this is a known incomplete state, not an intentional design choice.

---

### Recommendation

Wire the real committee-scheme certificate verifier (e.g., `implVerifyCert` from `WFALS` or `EveryoneVotes`) into the `validatePerasCert` implementation, replacing the stub. The validation must check: (1) aggregate BLS vote signature over `(electionId, candidate)`, (2) batch VRF proof verification for non-persistent voters, (3) quorum stake threshold, and (4) that the boosted block hash matches the certificate's declared target. Until this is done, the Peras certificate diffusion endpoint should not be exposed to untrusted peers.

---

### Proof of Concept

1. Connect to a node running this codebase as an unprivileged peer via the Peras certificate diffusion miniprotocol.
2. Construct a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = <hash of any block in the VolatileDB>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = 15}` unconditionally.
4. `addPerasCertAsync` enqueues the certificate; `chainSelSync` applies the 15-slot weight boost to the named block and calls `chainSelectionForBlock`.
5. If the boosted block is on a fork, the node switches to that fork — despite no legitimate quorum of committee members having voted for it.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-342)
```haskell
  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-586)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig

    -- Verify VRF outputs for non-persistent voters (if any)
    case catMaybes (NonEmpty.toList optionalVRFKeysAndOutputs) of
      -- No non-persistent voters => no VRF outputs to verify
      [] -> do
        pure ()
      -- Some non-persistent voters => verify their aggregate VRF outputs
      vrfKeysAndOutputs -> do
        let (vrfVerificationKeys, vrfOutputs) =
              munzip
                . NonEmpty.fromList -- safe 'vrfKeysAndOutputs' /= []
                $ vrfKeysAndOutputs
        bimap InvalidCertSignature id $
          batchVerifyVRFOutputs
            vrfVerificationKeys
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs

    -- Return the list of voters attesting the election winner
    pure members
```
