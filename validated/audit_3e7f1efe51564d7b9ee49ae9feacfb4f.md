### Title
`validatePerasCert` Stub Always Accepts Any Peras Certificate — Bypass of Peras Certificate Verification Enabling Unauthorized Chain Boost - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production Peras certificate diffusion path calls `validatePerasCert` on every inbound certificate received from a peer, but the only deployed instance of `validatePerasCert` is a stub that unconditionally returns `Right` (success) for every input, performing zero cryptographic or eligibility checks. This is the direct analog of the external report's pattern: a protective check exists and is called, but the mechanism that would make it reject invalid inputs is permanently absent. Any unprivileged peer can inject an arbitrary `PerasCert` (with any round number and any boosted-block pointer) into a node's ChainDB, causing the Peras chain-selection boost to be applied to an attacker-chosen block.

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for accepting inbound certificates. The only concrete instance in the codebase is the "degenerate instance for all blks" at:

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
``` [1](#0-0) 

The function unconditionally wraps the caller-supplied `cert` in `Right`, assigning it the full `perasWeight`. No signature is checked, no committee eligibility is verified, no round-number bounds are enforced.

**Production call site — node-to-node cert diffusion:**

`makePerasCertPoolWriterFromChainDB` is the writer used in the live node-to-node handler. It passes `validatePerasCert mkPerasParams` directly as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

This writer is wired directly into the live `hPerasCertDiffusionClient` handler in `NodeToNode.hs`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [3](#0-2) 

**`processCerts` logic — the gate that is supposed to reject:**

`processCerts` calls `validateCert` on each new certificate and throws `PerasCertValidationError` if any returns `Left`. Because `validatePerasCert` never returns `Left`, the error branch is unreachable: [4](#0-3) 

**End-to-end exploit path:**

1. Attacker connects to a Cardano node as an ordinary peer (no keys required).
2. Attacker sends a crafted `PerasCert` message via the Peras cert diffusion mini-protocol, specifying any `pcCertRound` and any `pcCertBoostedBlock` (e.g., a point on an adversarial fork).
3. `hPerasCertDiffusionClient` → `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert` → `Right` (always).
4. The certificate is timestamped and added to the ChainDB via `ChainDB.addPerasCertAsync`.
5. Chain selection applies the Peras boost (`perasWeight`) to the attacker-chosen block, potentially making the node prefer a non-canonical or adversarial chain.

### Impact Explanation

**Critical — Bypass of Peras certificate verification enabling unauthorized chain boost.**

The Peras protocol's entire security model depends on certificates being unforgeable: only a quorum of legitimately elected committee members can produce a valid certificate. With `validatePerasCert` permanently returning `Right`, this invariant is completely absent. Any peer can:

- Inject a certificate boosting an arbitrary block on an adversarial fork, causing the node's chain selection to prefer that fork over the honest chain.
- Inject certificates for past or future rounds with arbitrary boosted-block pointers, corrupting the node's Peras state.

This matches the allowed impact scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

**High.** The Peras cert diffusion mini-protocol is active in the node-to-node stack. Any peer that can establish a connection (no credentials required) can send `PerasCert` messages. The stub is the only instance of `validatePerasCert` in the codebase; there is no fallback or override. The TODO comment explicitly acknowledges the missing validation.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:

1. Verifies the certificate's aggregate BLS signature against the claimed committee members' public keys.
2. Checks that the claimed voters form a quorum (total stake ≥ threshold) under the stake distribution for the relevant epoch.
3. Verifies each voter's eligibility (committee membership, VRF proof for non-persistent members).
4. Validates that `pcCertRound` falls within the expected range relative to the current slot.

Until the full committee-selection plumbing is in place, the cert diffusion inbound handler should be disabled or should reject all inbound certificates rather than accepting them unconditionally.

### Proof of Concept

**Deterministic reasoning (no live network required):**

```
Peer sends PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialPoint }
  → hPerasCertDiffusionClient (NodeToNode.hs:375)
  → objectDiffusionInbound → processCerts (PerasCert.hs:164)
  → validatePerasCert mkPerasParams cert
      = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
      -- ^^^ always Right, no check performed (SupportsPeras.hs:353-358)
  → addCert (WithArrivalTime now validatedCert)
  → ChainDB.addPerasCertAsync chainDB validatedCert
  → chain selection applies Peras boost to adversarialPoint
```

The `PerasValidationErr` branch in `processCerts` (line 183–185 of `PerasCert.hs`) is structurally unreachable because `validatePerasCert` has no code path that returns `Left`. [5](#0-4) [6](#0-5) [3](#0-2)

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
