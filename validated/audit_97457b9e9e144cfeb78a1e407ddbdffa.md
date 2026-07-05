### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate as valid. Any unprivileged peer can send a crafted `PerasCert` for an arbitrary block over the Peras certificate diffusion miniprotocol; the receiving node will accept it, store it, and re-run chain selection with the fake boost applied, potentially switching to an adversarial chain.

### Finding Description
The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a certificate before it is stored and used to boost a block in chain selection. The only deployed instance — the degenerate `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as an unconditional `Right`:

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

No signature, quorum, committee membership, or round-number check is performed. The `validatePerasCert mkPerasParams` call-site in the production certificate pool writer passes this stub directly:

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

`processCerts` then adds every cert that passes `validatePerasCert` (i.e., every cert) to the ChainDB via `addPerasCertAsync`, which triggers chain selection re-evaluation with the boost applied. [3](#0-2) 

This writer is wired directly into the node-to-node Peras certificate diffusion inbound handler, reachable by any connecting peer:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

The `ValidatedPerasCert` produced by the stub carries `vpcCertBoost = perasWeight params`, the full Peras weight, which is used by chain selection to prefer the boosted block over competing candidates. [5](#0-4) 

### Impact Explanation
An unprivileged peer can inject a `PerasCert` naming any block — including a block on an adversarial fork — and the receiving node will treat it as a legitimately quorum-certified certificate carrying the full Peras weight boost. Chain selection will then prefer the adversarial block over the honest chain tip. This is a **Peras voting/certificate check bypass** that enables unauthorized certificate acceptance and a chain-selection manipulation, matching the "High" impact tier: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation
The Peras certificate diffusion miniprotocol is open to any node-to-node peer; no authentication or stake requirement is needed to connect and submit certificates. The bypass requires only that the attacker send a well-formed CBOR-encoded `PerasCert` message. The stub is the only deployed instance and is used in the production `mkHandlers` path. Likelihood is **high** for any deployment that activates the Peras certificate diffusion protocol.

### Recommendation
Replace the stub `validatePerasCert` implementation with a real check that verifies:
1. The certificate's BLS/aggregate signature over the claimed quorum of committee votes.
2. That the signers are eligible committee members for the stated round.
3. That the total stake of the signers meets the quorum threshold (`stakeAboveThreshold`).
4. That the round number is within the acceptable window relative to the current chain tip.

Until the real implementation is ready, the inbound certificate diffusion handler should reject all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them.

### Proof of Concept
1. Connect to a target node as a peer over the node-to-node protocol with Peras certificate diffusion enabled.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of an adversarial block>`.
3. Send it via the `ObjectDiffusion` inbound protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })` unconditionally.
5. `addPerasCertAsync chainDB` stores the cert and triggers chain selection.
6. Chain selection now sees the adversarial block as carrying the full Peras weight boost and may switch to the adversarial fork. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L111-137)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-390)
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
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
```
