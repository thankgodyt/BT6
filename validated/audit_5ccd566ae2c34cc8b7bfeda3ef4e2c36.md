### Title
`validatePerasCert` Unconditionally Accepts Any Inbound Peras Certificate Without Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. This function is wired directly into the live `PerasCertDiffusion` miniprotocol inbound handler. Any unprivileged peer can therefore inject an arbitrary `PerasCert` — pointing to any block of their choosing — and the node will accept it, store it in the `PerasCertDB`, and trigger chain selection with the fabricated Peras weight boost applied to the attacker-chosen block.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the codebase — a catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements this as:

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

This stub is the **only** `BlockSupportsPeras` instance in the repository; there is no more-specific override for Cardano block types. [2](#0-1) 

The inbound certificate diffusion path calls this function directly. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

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
``` [3](#0-2) 

`processCerts` calls `validateCert` on every certificate not already in the DB, and adds all that return `Right`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer passes.

This writer is wired into the live node-to-node `hPerasCertDiffusionClient` handler:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

The accepted certificate is then forwarded to `ChainDB.addPerasCertAsync`, which updates the `PerasWeightSnapshot` and triggers chain selection. [6](#0-5) 

---

### Impact Explanation

A crafted `PerasCert` carrying an attacker-chosen `pcCertBoostedBlock` is accepted without any check on:
- cryptographic aggregate signature over the votes
- committee eligibility of the claimed voters
- whether the boosted block actually exists on any known chain
- whether the round number is within the valid voting window

Once stored, the certificate causes `getPerasWeightSnapshot` to return a boosted weight for the attacker-chosen block. Chain selection then uses this snapshot to prefer the attacker's fork over the honest canonical chain, constituting a **chain selection safety failure** driven entirely by a network peer with no stake or keys.

This matches the **Critical** allowed impact: *Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance*, and the **High** allowed impact: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain*.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is active in the production node wiring (`NodeToNode.hs`). Any peer that can establish a node-to-node connection — which is the normal operating condition for a Cardano node — can send a `PerasCert` message. No stake, no keys, and no prior knowledge beyond the wire format are required. The attack is deterministic and requires a single well-formed CBOR-encoded certificate message.

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify the aggregate BLS signature over the constituent votes, check committee eligibility for each claimed voter against the epoch's stake distribution, and confirm the boosted block is a known block within the valid Peras voting window.
2. **Remove the catch-all degenerate instance** (`instance StandardHash blk => BlockSupportsPeras blk`) before the Peras miniprotocol is enabled on any network, or gate the miniprotocol behind a feature flag that is off until the real instance is in place.
3. **Add a property test** asserting that `validatePerasCert` rejects certificates with invalid signatures, unknown voters, or out-of-window round numbers.

---

### Proof of Concept

```
Attacker (unprivileged peer)                    Honest Node
        |                                              |
        |  -- PerasCertDiffusion connect ----------->  |
        |                                              |
        |  -- ObjectIds: [roundNo=42] -------------->  |
        |                                              |
        |  -- PerasCert { pcCertRound = 42,            |
        |       pcCertBoostedBlock =                   |
        |         attacker_fork_tip } -------------->  |
        |                                              |
        |                          processCerts called |
        |                  validatePerasCert returns   |
        |                  Right (no checks at all)    |
        |                                              |
        |                  ChainDB.addPerasCertAsync   |
        |                  PerasWeightSnapshot updated |
        |                  Chain selection re-run:     |
        |                  attacker_fork_tip gets      |
        |                  +perasWeight boost          |
        |                  Node switches to attacker   |
        |                  fork if weight tips balance |
```

The attacker needs only to know the wire format of `PerasCert blk` (a round number and a block point), both of which are public. No cryptographic material is required. The node will accept the certificate, boost the attacker-chosen block, and potentially switch to the attacker's fork. [1](#0-0) [7](#0-6) [8](#0-7) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
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
