### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Submitted Certificates, Enabling Unauthorized Chain Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic or committee-membership checks. Because the Peras certificate diffusion mini-protocol is fully wired into the node-to-node stack, any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted as `ValidatedPerasCert` and forwarded to `ChainDB.addPerasCertAsync`, where they influence chain selection by boosting the weight of an attacker-chosen block. This is a direct analog to the external report's "anyone can call `createProject`" pattern: just as any caller could claim ownership of a collection without authentication, any peer can claim that a block has been Peras-certified without presenting any proof.

---

### Finding Description

**Root cause — unconditional acceptance in `validatePerasCert`:**

The default `BlockSupportsPeras` instance, which covers all `StandardHash blk` (i.e., every production block type), implements `validatePerasCert` as:

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

The function ignores the certificate's content entirely and wraps it in `ValidatedPerasCert` with a non-zero boost weight. No committee membership check, no aggregate signature verification, and no round-number plausibility check is performed.

**Reachable entry path — NTN `PerasCertDiffusion` protocol:**

The node-to-node handler wires this directly into the live network stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` only rejects a batch when `validateCert` returns `Left`; since `validatePerasCert` never does, every inbound certificate passes:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

**Effect on chain selection:**

Accepted certificates are stored in `PerasCertDB` and their boost weight is reflected in the `PerasWeightSnapshot` used by chain selection. A certificate boosting block `B` increases `B`'s effective chain weight, potentially causing the node to switch to a fork it would otherwise reject. [5](#0-4) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate verification enabling unauthorized chain selection manipulation.**

An unprivileged peer can craft a `PerasCert` for any `(round, block)` pair and have it accepted as a `ValidatedPerasCert` with full boost weight. By targeting a block on a minority fork, the attacker can make an honest node's chain selection prefer that fork over the honest chain. Because Peras certificates are designed to provide finality guarantees, accepting forged certificates undermines the safety property that Peras is intended to strengthen: a node may be made to treat an adversarially chosen block as "boosted" and switch to a chain that honest nodes have not certified.

This matches the allowed impact category: **"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."**

---

### Likelihood Explanation

**Likelihood: High.**

The attack requires only a standard NTN connection — no privileged keys, no stake, no prior relationship with the target node. The `PerasCertDiffusion` protocol is unconditionally enabled in the node-to-node application stack. The attacker needs only to:
1. Connect to the target node as a peer.
2. Send a `PerasCert` message with a chosen `(round, block)` pair.

No brute force, no cryptographic break, and no operator compromise is required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real committee-membership and aggregate-signature check before the Peras certificate diffusion protocol is enabled in production. Until that check is implemented, the `PerasCertDiffusion` inbound handler should either be disabled or should reject all inbound certificates at the protocol level rather than delegating to a no-op validator. The TODO reference to issue #120 confirms this is a known gap; it must be resolved before Peras is activated on any network where the diffusion protocol is reachable by untrusted peers. [6](#0-5) 

---

### Proof of Concept

**Private-testnet reproduction sequence:**

1. Start a node with the Peras certificate diffusion protocol enabled (default in the current codebase).
2. From an attacker-controlled peer, connect via NTN and send a `PerasCert` message targeting block `B` on a minority fork at round `R`:
   ```
   PerasCert { pcCertRound = R, pcCertBoostedBlock = blockPoint B }
   ```
3. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. The certificate is timestamped and passed to `ChainDB.addPerasCertAsync`.
5. Chain selection re-runs with the boosted weight for block `B`; if the boost is sufficient, the node switches to the fork containing `B`.
6. The attacker has caused the honest node to prefer an adversarially chosen chain without possessing any committee key or stake. [1](#0-0) [7](#0-6) [8](#0-7)

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
