### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates, Bypassing BLS Signature Verification — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` without performing any cryptographic or semantic validation. This function is wired directly into the production certificate ingestion path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore send a crafted `PerasCert` carrying an invalid BLS aggregate signature, have it accepted as valid, stored in the `PerasCertDB`, and used to boost an arbitrary block's weight in chain selection — bypassing the Peras quorum requirement entirely.

---

### Finding Description

**Analog mapping.** The external report describes a pattern where a resource (the Ignite fee) is committed before off-chain BLS proof validation completes, and the failure path does not restore it. The analog here is structurally identical: the BLS aggregate-signature verification step that should gate certificate acceptance is absent from the validation function, so the "resource" — the Peras chain-weight boost — is always committed regardless of certificate validity.

**Root cause — stub validation.**

In `SupportsPeras.hs` lines 350–358, the default instance of `BlockSupportsPeras` implements `validatePerasCert` as:

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

Every certificate, regardless of content, is wrapped in `Right` and returned as `ValidatedPerasCert`. [1](#0-0) 

**Production ingestion path.**

`makePerasCertPoolWriterFromChainDB` is the production writer for inbound peer certificates. It passes `validatePerasCert mkPerasParams` directly as the validation callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

**`processCerts` never rejects.**

`processCerts` partitions validation results into errors and successes. Because `validatePerasCert` always returns `Right`, the error list is always empty, the rejection branch (`throw (PerasCertValidationError errs)`) is never reached, and every certificate is unconditionally forwarded to `addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)   -- unreachable
``` [3](#0-2) 

**Chain selection consequence.**

`addPerasCertAsync` enqueues the certificate for processing by `chainSelSync`. That function adds the certificate to the `PerasCertDB` and triggers chain selection for the boosted block, potentially switching the node to a different fork:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The concrete BLS verification logic (`verifyAggregateVoteSignature`) already exists in `Ouroboros.Consensus.Peras.Crypto.BLS` but is not called from the validation path. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` with:
- An arbitrary `pcCertRound` (any round number)
- An arbitrary `pcBoostedBlock` (any block hash, including one on a competing fork)
- A random or forged `pcSignature` (BLS aggregate signature)

Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and used to boost the target block's weight in chain selection. This allows the attacker to:

1. **Bypass the Peras quorum requirement** — no actual committee votes are needed; a single peer can forge a certificate claiming any block won any round.
2. **Manipulate chain selection** — by boosting a block on a weaker or adversarial fork, the attacker can cause an honest node to prefer a non-canonical chain, constituting a consensus safety failure.

This is a bypass of Peras certificate/BLS-signature validation that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires no cryptographic material, no stake, and no privileged access. Any peer connected via the Peras certificate mini-protocol can send a well-formed CBOR-encoded `PerasCert` with arbitrary fields. The `PerasCert` type is fully serialisable and its `FromCBOR` instance performs no semantic checks. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Aggregates the public keys of the claimed voters using `aggregateVoteVerificationKeys`.
2. Verifies the BLS aggregate signature via `verifyAggregateVoteSignature` against the round number and boosted block.
3. Verifies each claimed voter's committee eligibility (persistent membership or VRF-based non-persistent eligibility proof).
4. Confirms the claimed voters collectively meet the quorum threshold.

The cryptographic primitives for all of these steps already exist in `Ouroboros.Consensus.Committee.Crypto.BLS` and `Ouroboros.Consensus.Peras.Crypto.BLS`. [7](#0-6) 

---

### Proof of Concept

1. Connect to a Peras-enabled node via the Peras certificate object-diffusion mini-protocol.
2. Craft a `PerasCert` CBOR payload:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcBoostedBlock` = the hash of a block on a competing (weaker) fork
   - `pcSignature` = 48 zero bytes (invalid BLS signature)
3. Send the payload. The node calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. `processCerts` adds the certificate via `addPerasCertAsync`.
5. `chainSelSync` processes the certificate, adds it to the `PerasCertDB`, and triggers `chainSelectionForBlock` for the boosted block.
6. The node's chain selection now treats the competing fork as having additional Peras weight and may switch to it. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L495-531)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L251-260)
```haskell
  verifyAggregateVoteSignature
    _
    aggPk
    roundNo
    boostedBlock
    aggSig = do
      BLS.verifyWithRole @SIGN
        (unPerasBLSCryptoAggregateVoteVerificationKey aggPk)
        (hashVoteSignature roundNo boostedBlock)
        (unPerasBLSCryptoAggregateVoteSignature aggSig)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L64-77)
```haskell
instance FromCBOR PerasCert where
  fromCBOR = do
    decodeListLenOf 4
    pcRoundNo <- fromCBOR
    pcBoostedBlock <- fromCBOR
    pcVoters <- fromCBOR
    pcSignature <- fromCBOR
    pure
      PerasCert
        { pcRoundNo
        , pcBoostedBlock
        , pcVoters
        , pcSignature
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L241-254)
```haskell
  forall r msg.
  ( SignableRepresentation msg
  , HasBLSContext r
  ) =>
  PublicKey r ->
  msg ->
  Signature r ->
  Either String ()
verifyWithRole pk msg (Signature sig) =
  verifyDSIGN
    (blsCtx (Proxy @r) (publicKeyScope pk))
    (unPublicKey pk)
    msg
    sig
```
