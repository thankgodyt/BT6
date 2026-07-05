### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts Any Certificate from Any Peer — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` method is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. This stub is wired directly into the production Peras certificate diffusion path. Any unprivileged peer can therefore inject a crafted certificate for an arbitrary block, have it accepted as "validated," and trigger chain selection that boosts that block's weight — potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — the stub validator**

In the universal `BlockSupportsPeras` instance (the only instance in the codebase, applying to all block types including `CardanoBlock`):

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

No signature is verified, no committee membership is checked, no round-number bounds are enforced. Every `PerasCert` from every peer is wrapped in `ValidatedPerasCert` and returned as `Right`. [1](#0-0) 

**Production entry path**

`makePerasCertPoolWriterFromChainDB` — the production writer used by the Peras certificate diffusion mini-protocol — passes this stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls this validator on every inbound certificate. Because validation always succeeds, every certificate is timestamped and forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

In the production path `addCert` is `void . ChainDB.addPerasCertAsync chainDB`, which enqueues the certificate for chain selection processing. [4](#0-3) 

**Chain-selection consequence**

`addPerasCertAsync` enqueues the certificate into `cdbChainSelQueue`. The chain-selection loop processes it and applies the `vpcCertBoost` weight to the boosted block. If the boosted block is in the VolatileDB and the resulting weighted chain is heavier than the current selection, the node switches forks. [5](#0-4) 

**Analog to M-02**

The Lybra bug records a deposit amount at T₁ and ignores the negative rebase at T₂, so the stale recorded value is used at T₃ (withdrawal) — the protocol treats a stale accounting entry as if it still reflects the current on-chain state. Here, `validatePerasCert` records a certificate as `ValidatedPerasCert` at T₁ without ever performing the cryptographic check that should determine its validity. The `Validated` wrapper is then consumed at T₃ (chain selection) as authoritative proof of validity — but the underlying cryptographic state was never actually verified. In both cases a value is stamped as "correct" at recording time while the check that should have changed its status is silently skipped, and downstream logic trusts the stamp unconditionally.

---

### Impact Explanation

A Peras certificate boosts the weight of a specific block in chain selection. An attacker who can send a single crafted `PerasCert` message — naming any block in the VolatileDB as the boosted block — causes the receiving node to treat that block as having extra weight. If the adversary's chain accumulates enough such boosts it becomes heavier than the honest chain, and the node switches to it. This is a **consensus safety failure**: an unprivileged peer can make an honest node accept an invalid certificate and prefer a non-canonical or adversary-controlled chain, satisfying the Critical impact criterion "Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance."

---

### Likelihood Explanation

High. The attack requires only a TCP connection to the node's Peras certificate diffusion endpoint. No stake, no keys, no prior chain knowledge is needed. The attacker sends one `PerasCert` message with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The stub validator accepts it unconditionally. The attack is repeatable across all rounds and all nodes running this code.

---

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert`: verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the public keys of the claimed committee members, and verify that those members are eligible for the given round according to the epoch's committee selection output.
2. **Until real validation is in place**, gate the certificate diffusion path behind a feature flag that is disabled by default, so the stub cannot be reached from the network.
3. Track the concrete validation requirements in the referenced issues (tweag/cardano-peras#73, tweag/cardano-peras#120) and block deployment of the diffusion path on their resolution.

---

### Proof of Concept

```
Attacker node  ──[PerasCert { pcCertRound = R, pcCertBoostedBlock = adversaryBlock }]──►  Honest node
                                                                                              │
                                                                                    validatePerasCert
                                                                                    always returns Right
                                                                                              │
                                                                                    addPerasCertAsync
                                                                                              │
                                                                                    chainSelSync
                                                                                    boosts adversaryBlock
                                                                                    weight by perasWeight
                                                                                              │
                                                                                    if weighted(adversaryChain)
                                                                                    > weighted(honestChain):
                                                                                    node switches to adversary fork
```

No cryptographic material is required. The attacker constructs a `PerasCert` with any desired `pcCertRound` and `pcCertBoostedBlock`, sends it over the Peras certificate diffusion mini-protocol, and the stub at lines 353–358 of `SupportsPeras.hs` accepts it unconditionally, forwarding it into chain selection. [6](#0-5) [7](#0-6) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```
