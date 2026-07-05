### Title
Degenerate `BlockSupportsPeras` Instance Unconditionally Accepts All Peras Certificates Without BLS Signature Verification, Enabling Unauthorized Certificate Acceptance and Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines the interface for Peras certificate and vote validation. The only instance provided is an explicitly acknowledged degenerate catch-all placeholder that unconditionally accepts every Peras certificate without performing any BLS aggregate signature verification. This instance is used directly in the production `processCerts` code path, which is reachable by any unprivileged peer via the Peras certificate ObjectDiffusion miniprotocol. An attacker can inject arbitrary crafted Peras certificates that boost any block's chain selection weight, potentially causing honest nodes to switch to non-canonical chains.

---

### Finding Description

`BlockSupportsPeras` in `SupportsPeras.hs` is the typeclass that governs Peras certificate and vote validation. The only instance in the codebase is a degenerate catch-all, explicitly marked with a TODO:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
  ...
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

`validatePerasCert` always returns `Right` regardless of the certificate's content. No BLS aggregate signature is checked. No round number bounds are enforced. No boosted-block hash is verified against the chain. Every certificate, valid or crafted, is unconditionally promoted to `ValidatedPerasCert`.

This degenerate instance is the validator used in the production `makePerasCertPoolWriterFromChainDB` function:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
```

`processCerts` calls `validatePerasCert` on each inbound certificate and, if all pass, adds them to the ChainDB via `addPerasCertAsync`. Because `validatePerasCert` always succeeds, every certificate received from a peer is accepted and forwarded to chain selection.

The secondary defect, `getPerasCertInBlock _ = Nothing`, means the ledger state never records on-chain Peras certificate rounds, permanently breaking the cooldown-period coordination that `getLatestPerasCertOnChainRound` depends on.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and an arbitrary `pcCertBoostedBlock` pointing to any block hash, including a non-canonical or attacker-controlled block. Because `validatePerasCert` returns `Right` unconditionally, the certificate is accepted and added to the ChainDB. The ChainDB API documents that `addPerasCertAsync` "If this leads to a fork to be weightier than our current selection, this will trigger a fork switch." The accepted certificate carries `vpcCertBoost = perasWeight params`, a non-zero Peras weight boost. By targeting a non-canonical block, an attacker can make that block's chain appear heavier than the honest chain, causing the node to switch to a non-canonical fork. This is a bypass of Peras certificate BLS signature verification that enables unauthorized certificate acceptance and chain selection manipulation.

---

### Likelihood Explanation

The Peras certificate ObjectDiffusion miniprotocol infrastructure is present in production source files (not test or benchmark files). The `makePerasCertPoolWriterFromChainDB` and `processCerts` functions are production code. The degenerate `BlockSupportsPeras` instance is the only instance for all block types, including `CardanoBlock`. While `eraPerasRoundLength = HardFork.NoPerasEnabled` is currently set for all Shelley-based eras (with a TODO to enable it in the Dijkstra era), the certificate ingestion pipeline is structurally active and will accept any certificate delivered by a peer once the miniprotocol is negotiated. The likelihood is high once the Peras miniprotocol is enabled in a released node version, and the window for exploitation is the entire period between miniprotocol activation and deployment of proper BLS validation.

---

### Recommendation

1. **Do not enable the Peras certificate ObjectDiffusion miniprotocol in any released node version until `validatePerasCert` performs full BLS aggregate signature verification** against the committee's aggregate public key.
2. Replace the degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk` with era-specific instances (e.g., for `ShelleyBlock (Praos c) DijkstraEra`) that implement proper cryptographic validation using the concrete `V1.PerasCert` type and BLS verification from `Ouroboros.Consensus.Peras.Cert.V1`.
3. Implement `getPerasCertInBlock` to extract Peras certificates from blocks so that `shelleyLedgerLatestPerasCertRound` is correctly maintained and cooldown-period coordination is not silently broken.
4. Add a compile-time or runtime guard that prevents `processCerts` from being wired to the ChainDB unless a non-degenerate `validatePerasCert` is in scope.

---

### Proof of Concept

1. Connect to a Cardano node as an unprivileged peer and negotiate the Peras certificate ObjectDiffusion miniprotocol.
2. Craft a `PerasCert blk` value with:
   - `pcCertRound`: any `PerasRoundNo` not yet present in the node's cert DB
   - `pcCertBoostedBlock`: the `Point` of a non-canonical block the attacker wishes to boost
3. Send the crafted certificate to the node.
4. The node's `makePerasCertPoolWriterFromChainDB` calls `processCerts`, which calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally — no BLS signature is checked.
6. `addPerasCertAsync chainDB` is called with the accepted certificate.
7. Chain selection is re-evaluated with the non-canonical block now carrying a Peras weight boost, potentially triggering a fork switch to the attacker's preferred chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
