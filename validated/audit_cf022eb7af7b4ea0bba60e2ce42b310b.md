### Title
Peras Certificate Validation Stub Always Accepts Any Certificate from Unprivileged Peer — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the universal `BlockSupportsPeras` instance unconditionally returns `Right` (success) for every inbound Peras certificate, performing zero cryptographic or structural checks. This stub is wired directly into the production Peras certificate diffusion pipeline. Any unprivileged peer can send a crafted `PerasCert` message that will be accepted without verification and stored in the ChainDB, where it influences chain selection via the Peras boost weight.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only concrete instance — a universal degenerate instance covering all block types — implements this as an unconditional success:

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

No signature check, no round-number plausibility check, no issuer eligibility check, and no aggregate BLS verification is performed. The `PerasValidationErr` data type is a single-constructor unit (`= PerasValidationErr`) that can never be produced by this path. [2](#0-1) 

This stub is the function passed as the `validateCert` argument in `processCerts`, the inbound certificate processing function:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [3](#0-2) 

The production `makePerasCertPoolWriterFromChainDB` explicitly passes `validatePerasCert mkPerasParams` as that validator:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [4](#0-3) 

This writer is wired into the live node-to-node `hPerasCertDiffusionClient` handler in the production diffusion layer:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

The accepted certificate is then submitted to the ChainDB via `addPerasCertAsync`, where it participates in chain selection with a boost weight of `perasWeight params`.

The structural parallel to the external report is exact: the validation infrastructure is fully present (the `validatePerasCert` interface, the `processCerts` pipeline, the `PerasCertValidationError` exception, the `PerasValidationErr` error type), but the critical control — the actual cryptographic check — is never invoked. The function body is a stub that always succeeds, making the entire validation gate inaccessible in practice.

---

### Impact Explanation

**Impact: Critical** — Bypass of Peras certificate verification that enables unauthorized certificate acceptance.

An unprivileged peer can craft a `PerasCert` message with an arbitrary `pcCertRound` and `pcCertBoostedBlock` (pointing to any block, including an adversarial one). Because `validatePerasCert` always returns `Right`, the certificate passes the validation gate, is timestamped, and is stored in the ChainDB. The stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, a non-zero boost weight. Chain selection then uses this boost to prefer the attacker-nominated block over the honest chain tip, constituting a chain-selection manipulation via unauthorized certificate acceptance.

This falls squarely within: *"Critical. Bypass of … certificate … checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

**Likelihood: High.** The Peras certificate diffusion mini-protocol is active in the production node-to-node handler. Any peer that speaks the `PerasCertDiffusion` protocol can send a batch of certificates. No stake, no key material, and no prior relationship with the node is required. The attacker only needs to connect as a standard peer and send a well-formed CBOR-encoded `PerasCert` message. The stub validation ensures the certificate is accepted on the first attempt.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real cryptographic check before the Peras certificate diffusion protocol is enabled on any network where chain selection is influenced by Peras boosts. At minimum:

1. Verify the aggregate BLS signature over the certificate's `(electionId, candidate)` pair using the committee's aggregate verification key (mirroring the logic already implemented in `implVerifyCert` for `EveryoneVotes` and `WFALS`).
2. Verify that the certificate's round number is within the current Peras window.
3. Verify that the boosted block is a known, valid block on a plausible chain.

Until real validation is in place, the `hPerasCertDiffusionClient` handler should either be disabled or the `validatePerasCert` stub should return `Left PerasValidationErr` unconditionally to prevent acceptance of any certificate.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker connects to a production node as a standard peer supporting `NodeToNodeV_x` with Peras diffusion enabled.
2. Attacker sends a `PerasCertDiffusion` message containing a `PerasCert` with:
   - `pcCertRound = <any round number not yet in the DB>`
   - `pcCertBoostedBlock = <point of an adversarial block>`
3. The node's `objectDiffusionInbound` handler calls `opwAddObjects` on `makePerasCertPoolWriterFromChainDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` — no check performed.
6. `partitionEithers` sees zero errors; `addCert` is called.
7. `ChainDB.addPerasCertAsync` stores the certificate; chain selection applies the boost to `pcCertBoostedBlock`.

**Relevant code path (condensed):**

```
NodeToNode.hs: hPerasCertDiffusionClient
  → makePerasCertPoolWriterFromChainDB          (PerasCert.hs:118)
    → processCerts … (validatePerasCert mkPerasParams) …  (PerasCert.hs:126)
      → validatePerasCert params cert = Right …           (SupportsPeras.hs:353)
        → ChainDB.addPerasCertAsync chainDB cert          (PerasCert.hs:132)
``` [6](#0-5) [7](#0-6) [5](#0-4)

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
