### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Certificates, Enabling Unauthorized Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production Peras certificate diffusion inbound handler in `NodeToNode.hs` accepts `PerasCert` objects from any connected peer and routes them through `makePerasCertPoolWriterFromChainDB`. The certificate validation step is delegated to `validatePerasCert`, which is implemented in the universal `BlockSupportsPeras` instance as an unconditional stub that always returns `Right` — accepting every certificate regardless of its cryptographic content, round number, or boosted block. Because the `PerasCertDiffusion` miniprotocol is wired into the production node-to-node handler with no access control, any unprivileged peer can inject a crafted `PerasCert` pointing at an arbitrary block in the VolatileDB. The certificate is accepted, stored, and triggers `addPerasCertAsync`, which enqueues a chain-selection event that may cause the node to switch to a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`:**

The `BlockSupportsPeras` instance for `StandardHash blk` is explicitly marked as a degenerate placeholder "to get things to compile":

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

No signature check, no round-number check, no quorum check, no boosted-block existence check — every `PerasCert` is unconditionally promoted to `ValidatedPerasCert` with the full configured boost weight. [1](#0-0) 

**Production handler wires the stub into the live peer-facing protocol:**

`mkHandlers` in `NodeToNode.hs` constructs the `hPerasCertDiffusionClient` handler using `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on every inbound certificate before inserting it into the ChainDB via `addPerasCertAsync`. There is no access control, no peer-trust check, and no feature-flag guard visible at this call site:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
      ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
      , 10
      , 10
      )
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

**Accepted certificate triggers chain selection:**

`addPerasCertAsync` enqueues the certificate for processing by `chainSelSync`. The ChainDB model shows that any certificate whose boosted block is not yet immutable immediately re-runs chain selection with the boosted block receiving extra weight (`vpcCertBoost`):

```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
``` [3](#0-2) 

**ChainDB API confirms the async cert path leads to chain selection:** [4](#0-3) 

**`addPerasCertAsync` implementation enqueues to the chain-selection queue:** [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block currently in the VolatileDB as the boosted block. Because `validatePerasCert` returns `Right` unconditionally, the certificate is stored and chain selection is re-run with that block receiving the full Peras weight boost. If the boosted block is on a fork that would otherwise lose chain selection, the artificial boost can flip the outcome, causing the honest node to adopt a non-canonical chain. This is a **bypass of Peras certificate verification** that enables unauthorized chain selection manipulation — a consensus safety failure reachable by any connected peer with no stake or keys.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is registered in the production `initiatorAndResponder` bundle and is open to every node-to-node peer. The `BlockSupportsPeras` instance is a universal catch-all (`StandardHash blk`) with no Cardano-specific override present in the repository, so the stub is the active implementation. No privilege, stake, or key material is required to connect as a peer and send a `PerasCert` message. [6](#0-5) 

---

### Recommendation

1. **Block the inbound path until real validation exists.** Until a cryptographically sound `validatePerasCert` is implemented (tracking issue `cardano-peras#120`), the `hPerasCertDiffusionClient` handler should reject all inbound certificates (return a hard error or disable the miniprotocol via a feature flag), rather than silently accepting them through a stub.

2. **Replace the universal stub with a proper instance.** The `BlockSupportsPeras` instance for `StandardHash blk` must not be used in production. A Cardano-specific instance must verify the certificate's aggregate BLS signature, round number, and quorum before returning `Right`.

3. **Mirror the vote-path pattern.** The vote inbound handler already gates acceptance on a stake distribution lookup (`PerasVoteStakeDistr mempty` causes all votes to fail). The cert inbound handler should apply an equivalent guard until real validation is wired up.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker establishes a node-to-node connection to the target node (standard peer connection, no keys required).
2. Attacker sends a `PerasCertDiffusion` protocol message containing a crafted `PerasCert`:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <point of a fork block in VolatileDB> }
   ```
3. `hPerasCertDiffusionClient` → `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. `addPerasCertAsync` enqueues the cert to `cdbChainSelQueue`.
5. `chainSelSync` processes the cert: the fork block now carries the full Peras weight boost.
6. Chain selection switches the node's selection to the attacker-chosen fork, diverging from the canonical chain. [7](#0-6) [2](#0-1)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1268)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
        , perasVoteDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasVoteDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasVoteDiffusionServer version responderCtx))
            )
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L460-474)
```haskell
addPerasCert ::
  forall blk.
  (LedgerSupportsProtocol blk, LedgerTablesAreTrivial ExtLedgerState blk) =>
  TopLevelConfig blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  Model blk ->
  (AddPerasCertChainSelOutcome, Model blk)
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
 where
  secParam = configSecurityParam cfg
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-459)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
      PerasCertTicketNo ->
      STM m (Map PerasCertTicketNo (m (WithArrivalTime (ValidatedPerasCert blk))))
  -- ^ Get all known Peras certs with a ticket number strictly greater than the
  -- given one, in ascending order. The values are 'm' actions to allow
  -- implementations with on-disk storage.
  , getPerasCertIds :: STM m (Set PerasRoundNo)
  -- ^ Get the set of all Peras certificate round numbers currently in the
  -- database.
  , addPerasVoteWithAsyncCertHandling ::
      WithArrivalTime (ValidatedPerasVote blk) ->
      m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
  -- ^ Add a Peras vote to the vote database, returning the result of the
  -- vote addition. If a certificate is produced in the process (quorum
  -- reached), it will be added via 'addPerasCertAsync' under the hood, in
  -- which case the corresponding promise will be returned.
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
