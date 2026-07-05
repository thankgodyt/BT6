### Title
Unconditional `validatePerasCert` Stub Accepts All Peer-Supplied Peras Certificates, Enabling Unauthorized Chain-Selection Boosting - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` catch-all instance implements `validatePerasCert` as an unconditional stub that always returns `Right`, performing zero signature, quorum, or committee-membership checks. This stub is wired directly into the `hPerasCertDiffusionClient` miniprotocol handler in the production node, meaning any unprivileged peer can send a crafted `PerasCert` that is accepted without validation, added to the ChainDB, and used to boost an attacker-chosen block by `perasWeight` (15 blocks) in chain selection. The analog to the external report is exact: just as any caller could invoke `parameterize` to modify proposal state without authorization, any peer can inject a certificate to modify chain-selection state without authorization.

### Finding Description

**Root cause — unconditional stub:**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase) implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always 15
      }
```

Every certificate, regardless of content, passes "validation" and is stamped with a boost of `perasWeight = 15`. [1](#0-0) 

**Production wiring — cert pool writer:**

`makePerasCertPoolWriterFromChainDB` passes this stub as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)   -- always Right
``` [2](#0-1) 

`processCerts` accepts the entire batch when all certs pass validation (i.e., always), then calls `addPerasCertAsync` for each: [3](#0-2) 

**Production wiring — node-to-node handler:**

The cert pool writer is bound directly to `hPerasCertDiffusionClient`, the inbound side of the `PerasCertDiffusion` miniprotocol that every connected peer drives:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**Chain-selection side-effect:**

`addPerasCertAsync` enqueues the accepted certificate into the `cdbChainSelQueue`, which the background chain-selection thread processes. A `ValidatedPerasCert` with `vpcCertBoost = 15` causes the block at `pcCertBoostedBlock` to be treated as 15 blocks heavier in chain selection, potentially causing the node to switch to a fork that includes the boosted block. [5](#0-4) 

**Contrast with vote validation:**

The analogous `validatePerasVote` at least performs a stake-distribution lookup and rejects votes whose `pvVoteVoterId` is absent from the distribution. In production the distribution is `pure (PerasVoteStakeDistr mempty)`, so all votes are rejected. Certificates have no equivalent guard — they are always accepted. [6](#0-5) [7](#0-6) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` for any round `r` and any block point `p` reachable in the victim's VolatileDB. The certificate is accepted unconditionally, stored in the `PerasCertDB`, and submitted to chain selection with a boost of 15 blocks. If the boosted block is on a fork that is otherwise 1–14 blocks shorter than the current selection, the victim node will switch to that fork. This constitutes:

- **Bypass of Peras certificate/vote verification** — no aggregate-signature, quorum, or committee-membership check is performed.
- **Chain-selection manipulation** — an attacker can steer an honest node onto a non-canonical fork of their choosing, breaking the safety guarantee that the node follows the heaviest honest chain.

Severity: **Critical** — matches "Bypass of … certificate … checks … that enables unauthorized … certificate acceptance" and "chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical … chain."

### Likelihood Explanation

- **Attacker preconditions**: none beyond a standard peer connection (no keys, no stake, no operator access).
- **Entry path**: the `PerasCertDiffusion` miniprotocol is enabled for `NodeToNodeV_16` and above; any peer speaking that version can send `PerasCert` messages.
- **Reliability**: the stub is deterministic — it never rejects. The attack succeeds on every attempt as long as the boosted block is present in the victim's VolatileDB.

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:
1. Verifies the aggregate BLS signature against the public keys of the claimed committee members.
2. Confirms that the claimed committee members collectively hold stake above the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. Confirms committee membership via the epoch's stake distribution (analogous to the `lookupPerasVoteStake` check already present in `validatePerasVote`).

Until the real implementation is ready, the inbound cert handler should reject all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them, mirroring the effective behavior of the vote handler under the empty stake distribution.

### Proof of Concept

1. Connect to a victim node as a peer speaking `NodeToNodeV_16`.
2. Via the `PerasCertDiffusion` miniprotocol, send a single `PerasCert`:
   - `pcCertRound = <any round number>`
   - `pcCertBoostedBlock = <point of a block on a fork in the victim's VolatileDB>`
3. The victim's `objectDiffusionInbound` handler calls `opwAddObjects [cert]`, which calls `processCerts`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = 15 }`.
5. `addPerasCertAsync chainDB cert` enqueues the cert; the background thread processes it.
6. Chain selection re-runs with the boosted block weighted 15 blocks heavier.
7. If the fork containing `pcCertBoostedBlock` was within 14 blocks of the current tip, the victim switches to that fork — accepting a non-canonical chain chosen by the attacker. [8](#0-7) [9](#0-8) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
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
            controlMessageSTM
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-410)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```
