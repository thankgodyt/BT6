### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain-Selection Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The degenerate `BlockSupportsPeras` instance, which is the only active instance for all block types including production Cardano blocks, implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) without performing any cryptographic or structural validation. This stub is wired directly into the production node-to-node object-diffusion path via `makePerasCertPoolWriterFromChainDB`, which is called from `NodeToNode.hs`. Any unprivileged peer can therefore inject arbitrarily crafted Peras certificates that are accepted without challenge, stored in the ChainDB, and used to apply a `perasWeight` boost during chain selection.

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must reject invalid certificates before they enter the node's state. The only concrete instance in the codebase is the catch-all degenerate instance:

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
```

Every certificate, regardless of its content, is wrapped in `Right` and assigned the full `perasWeight`. No signature, round-number, boosted-block, or committee-membership check is performed. [1](#0-0) 

**Production call site — `makePerasCertPoolWriterFromChainDB`:**

The production writer that processes inbound certificates from peers explicitly passes this stub as the validator:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

**Wired into node-to-node networking:**

`makePerasCertPoolWriterFromChainDB` is referenced in `ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs`, the production diffusion layer that handles all peer connections. This means the stub validator is active on every node that runs the Peras object-diffusion mini-protocol. [3](#0-2) 

**`processCerts` accepts the batch and stores it:**

`processCerts` calls `validateCert` on each certificate; because the stub always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `ChainDB.addPerasCertAsync`. [4](#0-3) 

**Accepted certificates influence chain selection:**

The ChainDB exposes a `PerasWeightSnapshot` derived from stored certificates. `mkChainSelEnv` passes this snapshot as `weights` into every chain-selection invocation, where the `vpcCertBoost` field (set to `perasWeight params` by the stub) is applied to the boosted block. [5](#0-4) 

**Exploit flow:**

1. Attacker connects to a victim node as a normal peer (no special privileges required).
2. Attacker sends a crafted `PerasCert` via the Peras object-diffusion mini-protocol, specifying an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to an adversarial block.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is stored in the ChainDB with `perasWeight` boost.
5. On the next chain-selection run, the adversarial block receives the Peras boost, making it preferred over the honest chain tip.
6. The victim node switches to the adversarial chain.

### Impact Explanation

An unprivileged peer can inject any number of fake Peras certificates targeting any block hash. Because the boost is applied during chain selection, the attacker can cause the victim node to prefer a non-canonical, adversary-controlled chain over the honest chain. This is a **High** severity chain-selection integrity failure: it lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Ouroboros protocol.

### Likelihood Explanation

The attack requires only a standard peer connection — no stake, no keys, no operator access. The Peras object-diffusion mini-protocol is wired into the production `NodeToNode` layer. Any peer that can establish a connection can immediately exploit this. Likelihood is **High** once the Peras diffusion protocol is active on mainnet nodes.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The aggregate BLS signature over `(roundNo, boostedBlock)` against the declared committee members' public keys.
- That the declared voters are eligible committee members for the given round (committee membership proof / VRF eligibility).
- That the certificate's `pcCertRound` is within the expected window relative to the current chain tip.

Until real validation is implemented, the object-diffusion handler for Peras certificates should be disabled or gated behind a feature flag so that no peer-supplied certificate can reach the ChainDB.

### Proof of Concept

1. Run a node with the Peras object-diffusion mini-protocol enabled.
2. Connect as a peer and send a `PerasCert` CBOR message with:
   - `pcCertRound` = any `PerasRoundNo` not yet in the DB.
   - `pcCertBoostedBlock` = the `Point` of an adversarial block already in the node's VolatileDB.
3. Observe that `processCerts` accepts the certificate (no exception thrown, no disconnect).
4. Observe that the next chain-selection run applies `perasWeight` to the adversarial block, causing the node to switch to the adversarial chain if it is otherwise competitive.

The deterministic root cause is at:
- `validatePerasCert` stub: [6](#0-5) 
- Production call site: [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L146-185)
```haskell
-- | Process a batch of inbound Peras certificates received from a peer.
--
-- Certificates whose round number is already present in the database (as
-- determined by @alreadyInDbSTM@) are silently skipped. The remaining
-- certificates are validated; if /any/ certificate in the batch fails
-- validation, the entire batch is rejected by throwing a
-- 'PerasCertInboundException' (which should make us disconnect from the distant
-- peer, see 'withPeer' bracket function from `ouroboros-network`). Otherwise,
-- each valid certificate is timestamped with the current wall-clock time and
-- added to the database via @addCert@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1083-1101)
```haskell
mkChainSelEnv CDB{..} blockCache weights curChain punish =
  ChainSelEnv
    { lgrDB = cdbLedgerDB
    , bcfg = configBlock cdbTopLevelConfig
    , varInvalid = cdbInvalid
    , varTentativeState = cdbTentativeState
    , varTentativeHeader = cdbTentativeHeader
    , getTentativeFollowers =
        filter ((TentativeChain ==) . fhChainType) . Map.elems
          <$> readTVar cdbFollowers
    , blockCache
    , weights
    , curChain
    , validationTracer =
        TraceAddBlockEvent . AddBlockValidation >$< cdbTracer
    , pipeliningTracer =
        TraceAddBlockEvent . PipeliningEvent >$< cdbTracer
    , punish
    }
```
