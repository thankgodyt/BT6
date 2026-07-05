### Title
Peras Certificate Validation Is a No-Op Stub Allowing Unauthorized Certificate Acceptance and Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This stub is wired directly into the production certificate-diffusion inbound path. Any unprivileged peer can therefore inject crafted Peras certificates carrying an arbitrary round number and an arbitrary boosted-block pointer; those certificates are stored in the `PerasCertDB` and immediately influence chain selection through the Peras weight mechanism, letting an attacker make honest nodes prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation always succeeds**

`BlockSupportsPeras.hs` lines 350–358 define the only `BlockSupportsPeras` instance (described as a "degenerate instance for all blks to get things to compile"):

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

No signature check, no round-number bounds check, no boosted-block existence check — the function accepts every input unconditionally.

**Production wiring — stub is used in the live inbound path**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` (lines 118–137) is the production writer used when receiving certificates from peers. It passes `validatePerasCert mkPerasParams` as the validation callback:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
```

`processCerts` (lines 156–185 in the same file) is the inbound handler called for every batch of certificates arriving from a remote peer. It calls `validateCert` (bound to the stub above) for each certificate not already in the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert` never returns `Left`, the `(errs, _)` branch is unreachable; every certificate from every peer is unconditionally added to the `PerasCertDB`.

**Chain-selection consequence**

`PerasCertDB.getWeightSnapshot` (used in chain selection) returns a `PerasWeightSnapshot` derived from all stored certificates. Injected certificates boost attacker-chosen blocks, directly distorting the chain-order comparison performed by the Peras-aware chain-selection logic.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` value with:
- `pcCertRound` set to any round number (e.g., the current round)
- `pcCertBoostedBlock` pointing to any block hash (e.g., a minority-fork tip)

Because `validatePerasCert` always returns `Right`, the certificate passes `processCerts`, is stored in `PerasCertDB`, and its boost weight is included in the next `getWeightSnapshot`. Chain selection then treats the attacker-chosen block as having accumulated Peras boost weight it never legitimately earned, potentially causing the honest node to switch to or retain a non-canonical chain.

This is a **bypass of Peras certificate verification** enabling unauthorized certificate acceptance and chain-selection manipulation, matching the Critical impact class: *"Bypass of … certificate/vote verification … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

High. The attack surface is the Peras certificate diffusion miniprotocol, reachable by any peer that can establish a connection to the node. No keys, stake, or privileged access are required. The attacker only needs to construct a syntactically valid `PerasCert` CBOR value and send it in a certificate-diffusion message.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature (`pcSignature`) over `(pcRoundNo, pcBoostedBlock)` against the public keys of the claimed voters.
2. Checks that `pcRoundNo` is within the acceptable window relative to the current chain state.
3. Verifies VRF eligibility proofs for non-persistent voters (`NonPersistentPerasVoteEligibilityProof`).
4. Confirms that `pcBoostedBlock` refers to a block that is known and within the boosting window.

Until this is done, the certificate-diffusion inbound path should either be disabled or gated behind a feature flag that is off by default.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate diffusion miniprotocol.
2. Construct a `PerasCert` (CBOR-encoded per `ToCBOR PerasCert`) with:
   - `pcCertRound = <current round>`
   - `pcCertBoostedBlock = <hash of a minority-fork block>`
   - `pcVoters` = any non-empty bitmap (passes `fromCompactRepr` structural check)
   - `pcSignature` = any bytes (never verified)
3. Send the certificate in a diffusion batch.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{…}` unconditionally.
5. The certificate is stored in `PerasCertDB`; `getWeightSnapshot` now returns a snapshot that boosts the minority-fork block.
6. Chain selection on the honest node now assigns extra Peras weight to the attacker-chosen block, potentially causing a switch to the non-canonical fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
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
