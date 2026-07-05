### Title
Peras Certificate Verification Bypass via Degenerate `BlockSupportsPeras` Instance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines the required interface for Peras certificate and vote validation. A universal degenerate instance — `instance StandardHash blk => BlockSupportsPeras blk` — is provided that unconditionally accepts every inbound Peras certificate as valid, performing no cryptographic or protocol-required checks. This stub is wired directly into the production object-diffusion miniprotocol inbound path, meaning any unprivileged peer can inject arbitrary Peras certificates that are stored and used to influence chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `SupportsPeras.hs` declares the required interface for Peras certificate validation:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

A universal overlapping instance is provided for all `StandardHash blk` types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

This implementation **unconditionally returns `Right`** for every certificate, regardless of its content. No signature check, no committee membership check, no round-number plausibility check, and no quorum proof is performed.

Additionally, `getPerasCertInBlock` always returns `Nothing`:

```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
``` [2](#0-1) 

This degenerate instance is not confined to tests. It is the instance used in the production inbound certificate processing path. Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` in the object-diffusion miniprotocol pass `validatePerasCert mkPerasParams` as the validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
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

The `processCerts` function relies entirely on the supplied `validateCert` function to reject invalid certificates. Since `validatePerasCert` always returns `Right`, the rejection branch is never reached:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  -- All certs are valid => add them to the pool
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  -- Some certs are invalid => reject the whole batch
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

The accepted certificate is then stored in `PerasCertDB` with a boost weight (`vpcCertBoost = perasWeight params`) that is used in chain selection. The `implAddCert` function in `PerasCertDB/Impl.hs` performs no further validation — it only deduplicates by round number: [5](#0-4) 

The analog to the external report is exact: just as `BaseRewardPool4626` claims to implement ERC-4626 but is missing all required functions and events, the universal `BlockSupportsPeras` instance claims to implement the certificate validation interface but provides no actual validation, making the `ValidatedPerasCert` type-wrapper meaningless as a security boundary.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` (pointing to any block, including an adversarial fork tip). The certificate passes `validatePerasCert` unconditionally, is stored in `PerasCertDB`, and its boost weight is applied during chain selection. This constitutes a **bypass of Peras certificate verification** that enables unauthorized certificate acceptance and can cause an honest node to prefer a non-canonical or adversarially-chosen chain, violating the Peras protocol's chain-quality and common-prefix guarantees.

This matches the **Critical** impact category: bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance, and the **High** impact category: chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The object-diffusion miniprotocol for Peras certificates is reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message. The degenerate instance is the only instance in scope for all block types (including `CardanoBlock`), so there is no more-specific instance that would override it with real validation.

---

### Recommendation

1. **Remove or restrict the universal degenerate `BlockSupportsPeras` instance.** It should not be reachable from production code paths. Replace it with a compile-time error or a `NoBlockSupportsPeras` sentinel that prevents accidental use.

2. **Implement actual `validatePerasCert` logic** that verifies: committee membership of signers, cryptographic signatures over the certificate content, round-number consistency with the current chain state, and quorum threshold.

3. **Implement `getPerasCertInBlock`** to extract certificates embedded in blocks, so that chain selection correctly accounts for on-chain certificates.

4. **Gate the object-diffusion miniprotocol** for Peras certificates behind a feature flag that is only enabled when real validation is in place, analogous to how `srnEnableInDevelopmentVersions` gates experimental protocol versions. [6](#0-5) 

---

### Proof of Concept

1. Connect to a Cardano node as an unprivileged peer via the Peras object-diffusion miniprotocol.
2. Construct a `PerasCert` with `pcCertRound = <target round>` and `pcCertBoostedBlock = <adversarial fork tip point>`.
3. Send the certificate in a batch via the miniprotocol's inbound message.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which unconditionally returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
5. The certificate is stored in `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. The stored certificate's boost weight is applied during chain selection, causing the node to prefer the adversarially-specified block over the canonical chain tip. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Node/NetworkProtocolVersion.hs (L60-79)
```haskell
  --
  -- This is the latest version intended for deployment.
  --
  -- IMPORTANT Note that this is entirely independent of the
  -- 'Ouroboros.Consensus.Shelley.Node.TPraos.shelleyProtVer' field et al.
  latestReleasedNodeVersion ::
    Proxy blk -> (Maybe NodeToNodeVersion, Maybe NodeToClientVersion)

-- | A default for 'latestReleasedNodeVersion'
--
-- Chooses the greatest in 'supportedNodeToNodeVersions' and
-- 'supportedNodeToClientVersions'.
latestReleasedNodeVersionDefault ::
  SupportedNetworkProtocolVersion blk =>
  Proxy blk ->
  (Maybe NodeToNodeVersion, Maybe NodeToClientVersion)
latestReleasedNodeVersionDefault prx =
  ( fmap fst $ Map.lookupMax $ supportedNodeToNodeVersions prx
  , fmap fst $ Map.lookupMax $ supportedNodeToClientVersions prx
  )
```
