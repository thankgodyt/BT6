### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Provided Certificate, Enabling Unauthorized Chain-Selection Weight Boost — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that unconditionally returns `Right` — i.e., it performs zero cryptographic or structural validation. This stub is wired directly into the production NTN (Node-to-Node) Peras certificate diffusion inbound path. Any unprivileged peer can therefore inject an arbitrary `PerasCert` that is accepted, stored in the `ChainDB`, and used to apply a Peras weight boost to any block the attacker chooses, potentially triggering a fork switch to a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The degenerate `BlockSupportsPeras` instance, explicitly marked as a placeholder, implements `validatePerasCert` as:

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

This instance is the **only** instance in scope for all block types (`instance StandardHash blk => BlockSupportsPeras blk`). No cryptographic committee membership check, no signature verification, no round-number sanity check — every certificate is accepted.

**Production inbound path — `makePerasCertPoolWriterFromChainDB`:**

Both production pool writers call `validatePerasCert mkPerasParams` directly:

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

`processCerts` passes every non-duplicate certificate through `validateCert`; since `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `addCert`. [3](#0-2) 

**NTN wiring — `hPerasCertDiffusionClient`:**

The NTN handler registers `makePerasCertPoolWriterFromChainDB` as the inbound handler for every peer connection:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**Chain-selection side-effect — `addPerasCertAsync`:**

The `ChainDB` API documents the consequence explicitly:

```
addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [5](#0-4) 

**End-to-end exploit path:**

1. Attacker connects to a victim node as an ordinary NTN peer (no privileges required).
2. Attacker sends a crafted `PerasCert` naming any block point and any round number via the `PerasCertDiffusion` mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
4. The certificate is passed to `ChainDB.addPerasCertAsync`.
5. ChainDB applies the Peras weight boost to the attacker-chosen block; if that block is on a competing fork, `preferAnchoredCandidate` now prefers it and a fork switch is triggered.
6. The victim node rolls back its current selection and adopts the attacker-boosted chain.

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can make an honest node apply a Peras weight boost to any block of the attacker's choosing. Because `addPerasCertAsync` explicitly triggers a fork switch when the boosted block is on a heavier fork, the attacker can force the victim to abandon its canonical chain and adopt a non-canonical one. This violates the core Ouroboros chain-selection safety invariant and constitutes an unauthorized certificate acceptance bypass.

### Likelihood Explanation

**High.** The attack requires only a standard NTN peer connection — no keys, no stake, no operator access. The `PerasCertDiffusion` mini-protocol is enabled in the production NTN handler for all peers. The stub is the only instance in scope and carries explicit `TODO` markers acknowledging it is incomplete. Any node running this code with Peras diffusion enabled is reachable.

### Recommendation

1. **Replace the stub `validatePerasCert` with a real implementation** that verifies committee membership, cryptographic signatures, and round-number validity before returning `Right`. Gate the `Right` path on all checks passing.
2. **Do not wire the stub into production NTN handlers.** Until real validation is implemented, the `hPerasCertDiffusionClient` handler should either be disabled or should reject all inbound certificates.
3. **Add a regression test** that sends a crafted certificate from a peer and asserts it is rejected (not stored, no fork switch triggered).

### Proof of Concept

```
1. Start a node with Peras diffusion enabled (default NTN config).
2. Connect as a peer via the NTN PerasCertDiffusion mini-protocol.
3. Send a PerasCert message:
     PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <tip of competing fork> }
4. Observe: processCerts calls validatePerasCert → Right (no error).
5. Observe: addPerasCertAsync is called with vpcCertBoost = perasWeight params.
6. Observe: ChainDB triggers a fork switch if the boosted block is on a heavier fork.
Result: Victim node has rolled back its canonical chain to the attacker-chosen fork.
```

The deterministic root cause is the unconditional `Right` in `validatePerasCert` at `SupportsPeras.hs:353–358`, reachable from any NTN peer via `NodeToNode.hs:375–383` → `PerasCert.hs:118–133` → `PerasCert.hs:164–173` → `ChainDB.addPerasCertAsync`.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
