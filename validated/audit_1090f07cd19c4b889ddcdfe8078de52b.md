### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` always returns `Right` (valid) without performing any actual validation. The `processCerts` inbound handler in `PerasCert.hs` relies entirely on this function to gate certificate acceptance. Because the check is a no-op, any unprivileged peer can inject arbitrary Peras certificates into the local node's certificate database, causing chain selection to apply fraudulent weight boosts to attacker-chosen blocks.

---

### Finding Description

The `BlockSupportsPeras` catch-all instance, declared for all `StandardHash blk`, implements `validatePerasCert` as an unconditional success:

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

No check is performed on the certificate's round number, the boosted block's existence or validity on any chain, quorum membership, or any cryptographic proof. The function always returns `Right`.

This function is the sole validation gate in `processCerts`, the production inbound handler for Peras certificates received from peers over the object-diffusion mini-protocol:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

The only pre-filter is a round-number deduplication check (`Set.member` against `alreadyInDb`). If the attacker sends a certificate for a round number not yet in the database, `validateCert` (bound to `validatePerasCert mkPerasParams`) always returns `Right`, and the certificate is unconditionally added to the ChainDB via `addPerasCertAsync`. [3](#0-2) 

The `PerasWeightSnapshot` derived from these certificates is then consumed directly by chain selection:

```haskell
data ChainSelEnv m blk = ChainSelEnv
  { ...
  , weights :: PerasWeightSnapshot blk
  ...
  }
``` [4](#0-3) 

---

### Impact Explanation

Peras certificates provide weight boosts to specific blocks during chain selection. A fraudulent certificate pointing to a block on an adversarial fork inflates that fork's weight, causing an honest node to prefer the adversarial chain over the canonical one. This is a **bypass of Peras certificate validation** that enables unauthorized certificate acceptance and directly corrupts chain selection, matching the "Critical — Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance" and "High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

---

### Likelihood Explanation

The entry path is fully reachable by any unprivileged peer: the object-diffusion mini-protocol for Peras certificates is a standard peer-to-peer channel. No keys, stake, or operator access are required. The attacker only needs to connect as a normal peer and send a `PerasCert` message with a crafted `pcCertBoostedBlock` pointing to a block on their preferred fork and a `pcCertRound` not yet present in the target node's database. The degenerate instance is the only active implementation (no more-specific instance for production Cardano block types was found in the codebase). [5](#0-4) 

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that verifies:
1. The certificate's round number is within the valid range relative to the current chain tip.
2. The boosted block (`pcCertBoostedBlock`) exists on a known chain and is not older than `k` blocks.
3. The certificate carries a valid quorum proof (aggregate signature or equivalent) from the committee for that round.
4. The certificate has not been superseded by a later certificate for the same round.

Until the real implementation is in place, inbound certificates from peers should be rejected entirely (return `Left PerasValidationErr` unconditionally) rather than accepted unconditionally, to prevent the chain-selection corruption described above.

---

### Proof of Concept

1. Attacker connects to an honest node as a normal peer via the object-diffusion mini-protocol.
2. Attacker sends a `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round not yet in DB>, pcCertBoostedBlock = <point on adversarial fork> }
   ```
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally. [6](#0-5) 
4. The certificate is added to the ChainDB via `addPerasCertAsync`.
5. `implGetWeightSnapshot` now includes a weight boost for the adversarial block. [7](#0-6) 
6. The next chain selection run uses `weightedSelectView` with the inflated weight, potentially switching the node to the adversarial fork. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L993-996)
```haskell
      , oldSuffixSelectView =
          withEmptyFragmentToMaybe $
            weightedSelectView (configBlock cfg) weights oldSuffix
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1039-1050)
```haskell
-- | Environment used by 'chainSelection' and related functions.
data ChainSelEnv m blk = ChainSelEnv
  { lgrDB :: LedgerDB.LedgerDB' m blk
  , validationTracer :: Tracer m (TraceValidationEvent blk)
  , pipeliningTracer :: Tracer m (TracePipeliningEvent blk)
  , bcfg :: BlockConfig blk
  , varInvalid :: StrictTVar m (WithFingerprint (InvalidBlocks blk))
  , varTentativeState :: StrictTVar m (TentativeHeaderState blk)
  , varTentativeHeader :: StrictTVar m (StrictMaybe (Header blk))
  , getTentativeFollowers :: STM m [FollowerHandle m blk]
  , blockCache :: BlockCache blk
  , weights :: PerasWeightSnapshot blk
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```
