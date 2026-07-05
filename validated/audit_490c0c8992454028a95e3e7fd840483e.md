### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This function is wired directly into the production Peras certificate diffusion inbound miniprotocol handler. Any unprivileged peer that negotiates this protocol can inject arbitrary `PerasCert` messages that will be accepted, stored in the ChainDB, and used to boost arbitrary blocks in chain selection — without any committee membership, quorum, or signature check.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The `BlockSupportsPeras` instance for all `StandardHash blk` types (the only instance in the codebase) implements `validatePerasCert` as an unconditional success:

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

Every certificate, regardless of content, is wrapped in `Right ValidatedPerasCert` and assigned the full `perasWeight` boost. [1](#0-0) 

**Production inbound handler wires this stub directly:**

In the node-to-node handler setup, `hPerasCertDiffusionClient` is wired to `makePerasCertPoolWriterFromChainDB systemTime getChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validation callback:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

Inside `makePerasCertPoolWriterFromChainDB`, the validation call is:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

**`processCerts` accepts all certs that pass validation and adds them to ChainDB:**

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Since `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable. Every certificate from every peer is accepted. [4](#0-3) 

**Accepted certificates influence chain selection:**

Accepted certificates are added to the ChainDB via `addPerasCertAsync`, which triggers chain selection. The `vpcCertBoost` field (set to `perasWeight params` for every accepted cert) is read into `PerasWeightSnapshot` and used by `chainSelection` to prefer boosted blocks over unboosted ones. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` message claiming to certify any arbitrary block point for any round number. Because `validatePerasCert` always returns `Right`, the fake certificate:

1. Passes the inbound validation gate in `processCerts`.
2. Is stored in the `PerasCertDB` inside the ChainDB.
3. Contributes a full `perasWeight` boost to the certified block in `PerasWeightSnapshot`.
4. Causes `chainSelection` to prefer the boosted (adversarial) block over the honest chain tip.

This is a **bypass of Peras certificate/vote verification checks** that enables unauthorized certificate acceptance and chain selection manipulation — matching the allowed impact: *"Critical. Bypass of leader eligibility, VRF/KES/certificate/signature validation, PBFT/Praos/TPraos/Peras voting or certificate checks, or hot-key rules that enables unauthorized block, vote, or certificate acceptance."* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The Peras cert diffusion miniprotocol is fully wired into the production node-to-node handler record (`Handlers`) in `NodeToNode.hs`. Any peer that successfully negotiates a node-to-node version that includes this miniprotocol can immediately exploit this. No special keys, stake, or privileges are required — only the ability to connect as a peer. The attack is deterministic: every crafted certificate will be accepted.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify committee membership, quorum threshold, and cryptographic signatures before returning `Right`. The existing `TODO` at issue `#120` must be resolved before this protocol is active in production.
2. **Gate the miniprotocol on a feature flag**: until proper validation is in place, the Peras cert diffusion inbound handler should reject all certificates (return `Left`) or be disabled at the protocol negotiation level.
3. **Analog to the external report's fix**: just as `checkQuota` was restricted to only be callable by `IntentTokenMinting`, `validatePerasCert` must enforce that only structurally and cryptographically valid certificates — provably from an eligible quorum — can be accepted.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a target node as a standard peer and negotiates the node-to-node protocol version that includes the Peras cert diffusion miniprotocol.
2. Attacker sends a `PerasCert` message with:
   - `pcCertRound = <any round number, e.g. round 999>`
   - `pcCertBoostedBlock = <point of an adversarial block the attacker wants boosted>`
3. The message reaches `hPerasCertDiffusionClient` → `makePerasCertPoolWriterFromChainDB` → `processCerts`.
4. `validatePerasCert mkPerasParams cert` is called and unconditionally returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
5. The fake certificate is stored in the ChainDB via `addPerasCertAsync`.
6. Chain selection runs with the fake certificate's weight boost applied to the adversarial block.
7. If the adversarial block's boosted weight exceeds the honest chain's weight, the node switches to the adversarial chain.

**Expected outcome:** The node accepts and stores the fake certificate without any error, and chain selection may prefer the adversarial block — all triggered by an unprivileged peer with no keys or stake. [6](#0-5) [7](#0-6) [2](#0-1)

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
