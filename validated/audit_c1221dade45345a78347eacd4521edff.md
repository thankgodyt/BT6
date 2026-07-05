### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates Without Cryptographic or Semantic Checks - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

---

### Summary

The `validatePerasCert` function — the sole validation gate for inbound Peras certificates received from peers — is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. Any certificate a peer sends (invalid BLS aggregate signature, fabricated voter set, wrong quorum, wrong boosted block) is accepted, stored in the `PerasCertDB`, and used to influence chain selection. This is a direct analog to the reported pattern: a function that is supposed to check multiple sub-components (signature, voter eligibility, quorum threshold, boosted-block validity) but actually checks none of them.

---

### Finding Description

`BlockSupportsPeras` exposes `validatePerasCert` as the validation entry point for inbound certificates. The default implementation in the production source file is:

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

This stub is wired directly into both production pool-writer paths:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` — the inbound-certificate handler — calls `validateCert` on every certificate not already in the DB (filtered only by round number), then unconditionally adds all "validated" certificates:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` never returns `Left`, the error branch is unreachable. Every certificate from every peer passes.

A concrete `PerasCert` carries four fields that must all be validated: `pcRoundNo`, `pcBoostedBlock`, `pcVoters` (a non-empty map of seat indices to eligibility proofs), and `pcSignature` (an aggregate BLS signature over the election identifier and boosted block hash). None of these are checked. [5](#0-4) 

Once accepted, the certificate is forwarded to `chainSelSync`, which uses `getPerasCertBoostedBlock cert` to trigger chain selection for the boosted block, potentially causing the node to prefer a non-canonical chain: [6](#0-5) 

---

### Impact Explanation

**High.** An unprivileged peer can craft a `PerasCert` that:
- Claims to boost an arbitrary block (e.g., a block on a minority fork)
- Carries a fabricated or zeroed BLS aggregate signature
- Lists any voter set and seat indices

The certificate is accepted, stored, and used to boost the weight of the targeted block in `weightedSelectView`/`PerasWeightSnapshot`. Chain selection then compares the boosted weight of the attacker-chosen fork against the honest chain. If the fraudulent boost is large enough, the node switches to the attacker's preferred (non-canonical) chain. This constitutes a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

---

### Likelihood Explanation

**High.** The attack requires only that the adversary:
1. Connect to the target node as a peer (standard network access)
2. Send a `PerasCert` message via the ObjectDiffusion mini-protocol before any honest certificate for that round arrives

The round-number deduplication in `processCerts` (line 166) means the first certificate for a given round wins. A racing adversary who sends a fraudulent cert before honest peers propagate the real one will have it permanently stored and acted upon.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that checks all required fields before a certificate is accepted:

1. **Signature verification**: verify `pcSignature` is a valid BLS aggregate signature over `(pcRoundNo, pcBoostedBlock)` using the aggregate public key derived from `pcVoters`.
2. **Voter eligibility**: for each seat index in `pcVoters`, verify the eligibility proof (VRF output for non-persistent voters; committee membership for persistent voters).
3. **Quorum threshold**: verify the total stake weight of `pcVoters` meets the configured quorum.
4. **Round/block consistency**: verify `pcRoundNo` is within the valid range and `pcBoostedBlock` refers to a block in the correct slot window for that round.

Until this is implemented, inbound certificates from peers should not be used to influence chain selection.

---

### Proof of Concept

**Entry path**: peer → ObjectDiffusion mini-protocol → `processCerts` → `validatePerasCert` (stub, always `Right`) → `addCert` → `PerasCertDB` → `chainSelSync` → chain selection prefers boosted block.

**Concrete sequence**:
1. Attacker connects as a peer and identifies a minority-fork block `B'` at slot `s` in round `r`.
2. Attacker constructs `PerasCert { pcRoundNo = r, pcBoostedBlock = B', pcVoters = <any>, pcSignature = <zeroed> }`.
3. Attacker sends the cert before honest peers propagate the real cert for round `r`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight params}`.
5. Cert is stored; `chainSelSync` triggers chain selection for `B'`.
6. `weightedSelectView` adds `vpcCertBoost` to `B'`'s fragment weight; if this exceeds the honest chain's weight, the node switches to the attacker's fork. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
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
