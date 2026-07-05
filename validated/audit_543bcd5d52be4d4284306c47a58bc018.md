### Title
`validatePerasCert` Unconditionally Accepts Any Peras Certificate Without Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because `processCerts` — the inbound handler for Peras certificates received from peers via the ObjectDiffusion mini-protocol — calls this function as its sole gate before storing certificates, any unprivileged peer can inject arbitrary `PerasCert` values into the node's `PerasCertDB`. These certificates are then used to compute the Peras weight boost applied during chain selection, allowing a peer to steer the node toward a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub wired into production:**

The universal instance at `SupportsPeras.hs` lines 318–389 is declared as:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
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

Every field of the incoming `cert` is accepted verbatim — `pcCertRound` (the Peras round number) and `pcCertBoostedBlock` (the block being boosted) are never checked against any committee quorum, signature, or round-validity rule.

**Inbound path — `processCerts` uses this stub as its only validator:**

`makePerasCertPoolWriterFromChainDB` (the production writer used by the ObjectDiffusion mini-protocol) passes `validatePerasCert mkPerasParams` directly to `processCerts`:

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

`processCerts` partitions the results of `validateCert <$> certsNotAlreadyInDb`. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `addCert`: [3](#0-2) 

**Storage and chain-selection effect:**

`implAddCert` stores the certificate in `PerasCertDB` and updates `pcdsLatestCertSeen`. `implGetWeightSnapshot` then derives a `PerasWeightSnapshot` from the stored certificates, which is consumed by chain selection to apply the Peras weight boost (`vpcCertBoost = perasWeight params`) to the boosted block: [4](#0-3) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block hash and slot. Because `validatePerasCert` never rejects it, the certificate is stored and its `vpcCertBoost` weight is applied during chain selection. This allows the attacker to artificially boost a non-canonical or adversarial block, causing the honest node to prefer a chain it would otherwise reject. This is a **bypass of Peras certificate validation** that enables unauthorized certificate acceptance and materially weakens chain-selection authorization — matching the Critical/High impact tier for Peras voting or certificate check bypass.

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is active in the production codebase and reachable by any connected peer. No privileged keys, stake majority, or operator access are required. An attacker needs only to connect as a normal peer and send a crafted `PerasCert` message. The stub is present in the universal instance that covers all block types, so there is no era or configuration that avoids it.

### Recommendation

Replace the stub `validatePerasCert` body with real validation before the function is reachable from any network-facing path. At minimum, add a guard that rejects the call entirely (returning `Left PerasValidationErr`) until the real implementation is in place, so that the `processCerts` rejection branch is taken for all inbound certificates. The production writer (`makePerasCertPoolWriterFromChainDB`) must not be wired to a validator that unconditionally returns `Right`.

```haskell
-- Temporary safe stub: reject all certs until real validation is implemented
validatePerasCert _params _cert = Left PerasValidationErr
```

This mirrors the recommendation in the external report: add the missing check (`require(treasuryVault != address(0))`) before the irreversible operation. Here the irreversible operation is storing a certificate that permanently influences chain selection weight.

### Proof of Concept

1. Connect to a production node as an unprivileged peer via the ObjectDiffusion mini-protocol for Peras certificates.
2. Send a `PerasCert` with `pcCertRound = r` (any round not already in the DB) and `pcCertBoostedBlock` pointing to an adversarial block hash.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. `implGetWeightSnapshot` now includes this certificate; chain selection applies `vpcCertBoost` to the adversarial block, causing the node to prefer it over the honest chain tip. [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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
