### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` method is a stub that unconditionally returns `Right` for every certificate it receives, performing zero validation. Because this function is wired directly into the live Peras certificate diffusion inbound path, any unprivileged peer can inject arbitrary `PerasCert` objects — with any round number and any boosted block point — into the node's `PerasCertDB`. Those certificates immediately influence chain selection by adding spurious weight boosts, allowing an attacker to steer an honest node toward a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote validation. Its production instance (the `StandardHash blk =>` catch-all) contains a stub `validatePerasCert` that always succeeds:

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

No check is performed on the certificate's round number, the boosted block's existence or ancestry, or any cryptographic proof of committee authority.

This stub is consumed directly in the production inbound certificate diffusion path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate; if all pass (which they always do), each is timestamped and inserted into the database: [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` is wired into the live node-to-node handler in `NodeToNode.hs`: [4](#0-3) 

Once a certificate is in the `PerasCertDB`, `implGetWeightSnapshot` reads it and returns weight boosts for chain selection: [5](#0-4) 

The `ChainDB` exposes `getPerasWeightSnapshot` to the chain selection logic, so injected certificates directly affect which chain the node considers heaviest. [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block point as the boosted block and any round number. Because `validatePerasCert` never rejects anything, the certificate is stored and its `vpcCertBoost` (set to `perasWeight params`) is applied to the named block during chain selection. By boosting a block on a minority or adversarial fork, the attacker can cause an honest node to switch away from the canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion protocol is active in the node-to-node handler for any peer that speaks the relevant protocol version. No authentication or stake ownership is required to send a `PerasCert` message. The attacker only needs to connect as a peer and send a crafted certificate batch. The code path from peer message to `PerasCertDB` insertion is short and entirely deterministic.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that checks at minimum:

1. The certificate's boosted block point refers to a block that is a known ancestor of the current chain tip (or at least within the volatile window).
2. The round number is within the expected range relative to the current slot.
3. The certificate carries a valid aggregate cryptographic proof from a legitimately elected Peras committee (once the committee selection plumbing referenced in issue #120 is in place).

Until the full cryptographic check is available, a structural guard (round number bounds, block point ancestry) should be enforced to prevent trivially forged certificates from influencing chain selection.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects and speaks the Peras certificate diffusion mini-protocol (`hPerasCertDiffusionClient` in `NodeToNode.hs`).
2. Peer sends a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on an adversarial fork>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The certificate is inserted into `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. `implGetWeightSnapshot` includes the injected boost in the weight snapshot.
7. Chain selection now treats the adversarial fork as heavier, potentially switching the node's preferred chain. [1](#0-0) [7](#0-6) [4](#0-3)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```
