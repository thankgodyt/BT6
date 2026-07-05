### Title
Peras Certificate Verification Bypass: `validatePerasCert` Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or structural validation on inbound Peras certificates. Both production pool-writer constructors (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass this stub as the validation function to `processCerts`, which is the inbound-certificate handler called for every certificate received from an unprivileged peer. Any peer can therefore inject an arbitrary `PerasCert` — pointing to any block — and have it accepted, stored, and used to boost chain-selection weight.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:**

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

This is the **only** `BlockSupportsPeras` instance in the codebase — it is declared as the universal instance for all `StandardHash blk` and is therefore the instance used in production. [2](#0-1) 

**Wiring into the production inbound path:**

Both pool-writer constructors pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

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
``` [3](#0-2) 

**`processCerts` accepts every certificate that passes `validateCert`:**

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is stored.

**No committee membership, quorum, or signature check is performed.** The `PerasCert` data type carries only a round number and a block point:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound        :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [5](#0-4) 

An attacker can set `pcCertBoostedBlock` to any block point they choose.

**Accepted certificates influence chain selection.** Each accepted certificate is stored with `vpcCertBoost = perasWeight params` (currently `PerasWeight 15`). The `PerasCertDB` exposes a `getWeightSnapshot` used by chain selection to prefer boosted blocks. [6](#0-5) 

---

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can:
1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any adversarial block.
2. Send it via the Peras cert diffusion mini-protocol.
3. `validatePerasCert` returns `Right` unconditionally; the certificate is stored in the `ChainDB`.
4. The stored certificate applies a `PerasWeight 15` boost to the adversarial block in chain selection.
5. The honest node may prefer the adversarially boosted chain over the canonical chain, violating the Peras safety guarantee that only quorum-certified blocks receive a boost.

This directly maps to the allowed impact category: *"Critical. Bypass of … certificate/signature validation … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

**High.** The attack requires only a standard peer connection — no keys, no stake, no operator access. The Peras cert diffusion mini-protocol is an externally reachable endpoint. The bypass is deterministic: `validatePerasCert` has no conditional path that could reject a certificate. Any peer that can connect and speak the Peras cert diffusion protocol can exploit this.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify committee membership, quorum stake threshold (≥ 3/4 of active stake), and cryptographic signatures over the certified block. This is tracked in [cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120).
2. **Do not ship the degenerate `instance StandardHash blk => BlockSupportsPeras blk`** in production builds. Gate it behind a compile-time flag or replace it with a proper per-era instance before enabling the Peras cert diffusion mini-protocol on mainnet.
3. **Validate `pcCertBoostedBlock` against the local chain** before storing: reject certificates that boost blocks not present in the local VolatileDB or ImmutableDB.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer connects via node-to-node protocol
  → PerasCertDiffusion mini-protocol
  → objectDiffusionInbound
  → makePerasCertPoolWriterFromChainDB.opwAddObjects [crafted_cert]
  → processCerts ... (validatePerasCert mkPerasParams) ...
  → validatePerasCert mkPerasParams crafted_cert
      = Right (ValidatedPerasCert { vpcCert = crafted_cert, vpcCertBoost = 15 })
  → ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validated_cert)
  → PerasCertDB stores cert; getWeightSnapshot returns boost=15 for adversarial block
  → Chain selection prefers adversarially boosted block
```

No privileges, no keys, no stake required. The bypass is unconditional. [1](#0-0) [7](#0-6) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-137)
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
