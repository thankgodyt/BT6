### Title
Peras Certificate Validation Bypass via Unconditional `validatePerasCert` Acceptance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or semantic validation. Because this instance is wired into the live certificate-ingestion pipeline, an unprivileged peer can inject crafted certificates that assign arbitrary Peras boost weight to any block, directly manipulating chain selection on the receiving node.

---

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory validation gate for Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only deployed instance — the catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements this function as an unconditional pass-through:

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

No BLS aggregate-signature check, no voter-eligibility proof verification, no round-number bounds check, and no boosted-block existence check are performed. The certificate is stamped `ValidatedPerasCert` and assigned the full configured `perasWeight` regardless of its content.

This function is called directly from the production certificate-ingestion path in `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using the supplied validator; because the validator always returns `Right`, every certificate in every batch is accepted:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once stored, each certificate's `vpcCertBoost` is included in the `PerasWeightSnapshot` that drives chain selection:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [4](#0-3) 

`totalWeightOfFragment` then adds this boost to the chain-length metric used by chain selection:

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
``` [5](#0-4) 

The analogy to the external report is direct: just as a token creator can supply `address(0)` as the fee recipient and the system still calculates and transfers fees to that invalid address, a peer can supply a certificate with an arbitrary `pcCertBoostedBlock` and the system still calculates and applies the full boost weight to that block — because neither path validates the critical parameter before acting on it.

---

### Impact Explanation

**High — Chain selection manipulation by an unprivileged peer.**

A remote peer can craft a `PerasCert` whose `pcCertBoostedBlock` points to any block hash (including one on a minority fork). The certificate is accepted, stored, and its `perasWeight` is added to that block's chain-selection weight. If the injected boost is large enough relative to the honest chain's length advantage, the receiving node will switch to the attacker's preferred fork, violating chain-selection safety beyond the intended Ouroboros security assumptions.

Additionally, `takeVolatileSuffix` uses the boosted weight to determine the immutability boundary (`k`), so a sufficiently large injected boost can artificially shrink the volatile suffix, causing premature immutability of attacker-chosen blocks. [6](#0-5) 

---

### Likelihood Explanation

**Medium.**

The Peras certificate mini-protocol (`makePerasCertPoolWriterFromChainDB`) is wired into the live node. Any peer that can establish a connection and speak the Peras object-diffusion sub-protocol can send crafted certificates. The degenerate instance is the only deployed implementation — there is no fallback validation. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm the gap is known but unresolved in the current codebase.

---

### Recommendation

Replace the unconditional pass-through in `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the declared voter keys.
2. Verifies each voter's eligibility proof (persistent membership or VRF output) against the current committee.
3. Checks that the quorum threshold is met.
4. Rejects certificates whose `pcBoostedBlock` is `GenesisPoint` or whose `pcRoundNo` is outside the valid window.

Until the real implementation is ready, the node should refuse to process inbound Peras certificates rather than silently accept all of them.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the Peras object-diffusion mini-protocol.

2. Attacker constructs a crafted PerasCert:
     pcCertRound     = <any valid-looking round number>
     pcCertBoostedBlock = BlockPoint <slot> <hash of attacker's fork tip>
     -- pcSignature and pcVoters can be arbitrary bytes;
     -- validatePerasCert never inspects them.

3. Attacker sends the certificate batch to the honest node.

4. processCerts calls (validatePerasCert mkPerasParams) on the batch.
   validatePerasCert unconditionally returns:
     Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

5. The certificate is stored in PerasCertDB with full perasWeight boost.

6. implGetWeightSnapshot returns a PerasWeightSnapshot that includes
   (attacker's fork tip → perasWeight) in the weight map.

7. totalWeightOfFragment now scores the attacker's fork higher than the
   honest chain if perasWeight > (honest chain length - attacker fork length).

8. chainSelectionForBlock triggers a switch to the attacker's fork.
``` [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L209-213)
```haskell
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
