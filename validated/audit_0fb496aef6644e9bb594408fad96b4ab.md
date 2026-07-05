Now I have enough context to write the finding. Let me verify the exact line numbers for the key code paths.

### Title
Stub `validatePerasCert` Combined with First-Come-First-Served `PerasRoundNo` Deduplication Allows Any Unprivileged Peer to Inject an Arbitrary Peras Certificate and Corrupt Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasCert` implementation is an unconditional stub that always returns `Right`. Combined with a first-come-first-served deduplication rule in `implAddCert` (keyed on `PerasRoundNo`), any unprivileged peer can inject a crafted `PerasCert` for an arbitrary round, permanently occupying that round's slot in the `PerasCertDB`. The legitimate certificate for that round is then silently dropped without ever being validated or stored. The accepted malicious certificate is used directly by `chainSelSync` to trigger chain selection for the boosted (potentially non-canonical) block, and it becomes the `latestCertSeen` value that gates voting eligibility in subsequent rounds.

---

### Finding Description

**Root cause 1 — stub certificate validator (always `Right`):**

`validatePerasCert` in the degenerate `BlockSupportsPeras` instance performs no cryptographic check, no committee-membership check, and no stake-threshold check:

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

Every `PerasCert` received from any peer is unconditionally promoted to `ValidatedPerasCert`. The `PerasValidationErr` type is also a stub with a single constructor and no payload, confirming no real error path exists yet. [2](#0-1) 

**Root cause 2 — first-come-first-served deduplication by `PerasRoundNo`:**

`implAddCert` in `PerasCertDB/Impl.hs` enforces a strict uniqueness invariant: the first certificate received for a given round number wins permanently. Any subsequent certificate for the same round returns `PerasCertAlreadyInDB` and is discarded:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
``` [3](#0-2) 

The TODO comment on `implAddCert` itself acknowledges that non-trivial validation logic is missing: [4](#0-3) 

**Root cause 3 — pre-validation filtering in `processCerts`:**

`processCerts` reads the set of already-known round numbers atomically, then **filters out** any certificate whose round is already present **before** calling `validateCert`. This means a certificate that arrives second for round R is never validated — it is silently dropped:

```haskell
alreadyInDb <- atomically alreadyInDbSTM
let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
...
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
``` [5](#0-4) 

**Production wiring — reachable from any peer:**

The production node wires `makePerasCertPoolWriterFromChainDB` (which calls `validatePerasCert mkPerasParams`) directly to the `hPerasCertDiffusionClient` mini-protocol handler, making this path reachable from any connected peer without authentication: [6](#0-5) 

`makePerasCertPoolWriterFromChainDB` passes the stub validator explicitly: [7](#0-6) 

**Downstream security impact — chain selection and voting:**

Once the malicious certificate is stored, `chainSelSync` uses it to trigger chain selection for the boosted (attacker-chosen) block:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
case certRes of
  PerasCertDB.PerasCertAlreadyInDB -> idExitEarly ...
  PerasCertDB.AddedPerasCertToDB   -> ...
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [8](#0-7) 

Additionally, `getLatestCertSeen` — which is a **precondition for voting in any round except the very first** — is updated to the malicious certificate: [9](#0-8) 

---

### Impact Explanation

An unprivileged peer can:

1. Send a `PerasCert` for round R boosting an attacker-chosen block `B_evil` (any `Point blk` the attacker controls or knows about).
2. The stub `validatePerasCert` accepts it unconditionally.
3. Round R is permanently claimed in the `PerasCertDB`.
4. The legitimate certificate for round R (boosting the canonical block `B_good`) arrives later and is silently dropped by `processCerts` — it is never stored, never triggers chain selection for `B_good`.
5. `chainSelSync` triggers chain selection for `B_evil`, potentially causing the node to switch to a non-canonical chain if `B_evil`'s chain weight (plus the Peras boost) exceeds the canonical chain's weight.
6. `getLatestCertSeen` returns the malicious certificate, corrupting the voting precondition for all subsequent Peras rounds on this node.

This is a **bypass of Peras certificate validation** enabling unauthorized certificate acceptance, combined with a **chain selection error** that lets an unprivileged peer make an honest node prefer a non-canonical chain. The impact is not merely denial-of-service: the node actively uses the injected certificate for security-critical chain selection and voting eligibility decisions.

---

### Likelihood Explanation

- **Reachability**: The `hPerasCertDiffusionClient` handler is active in production node-to-node connections. Any peer that successfully completes the handshake can send `PerasCert` objects.
- **No stake or key required**: Because `validatePerasCert` is a stub, the attacker needs no committee membership, no VRF/KES keys, and no stake. Any peer can craft a `PerasCert{pcCertRound = R, pcCertBoostedBlock = anyPoint}`.
- **Timing**: The attacker only needs to send the malicious certificate before the legitimate one propagates. In a network with multiple peers, this is straightforward — the attacker simply sends the certificate immediately upon learning the current round number.
- **Persistence**: The effect is permanent for the lifetime of the `PerasCertDB` (until garbage collection removes old rounds), not just transient.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the Peras certificate diffusion mini-protocol is enabled in production. The validation must verify committee membership, BLS/cryptographic signatures, and stake-threshold quorum. The existing TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this.

2. **Enforce content-equality on duplicate round numbers**: `implAddCert` should not silently discard a certificate for an already-known round without checking whether the new certificate's `pcCertBoostedBlock` matches the stored one. A mismatch should be treated as an equivocation and the peer should be disconnected.

3. **Move the deduplication check after validation**: In `processCerts`, the `alreadyInDb` filter should be applied only as an optimization after validation passes, not as a pre-validation gate. This ensures that a malicious early-arriving certificate cannot permanently suppress a legitimate later-arriving one from being validated and logged.

---

### Proof of Concept

The following describes a private-testnet sequence that demonstrates the issue using the existing `PerasCertDB` API directly (analogous to the external report's test structure):

```haskell
-- Setup: two peers, one malicious, one legitimate
-- Both connect to the same honest node via hPerasCertDiffusionClient

-- Step 1: Malicious peer sends a certificate for round 42 boosting a non-canonical block
let maliciousCert = PerasCert
      { pcCertRound      = PerasRoundNo 42
      , pcCertBoostedBlock = nonCanonicalBlockPoint  -- attacker-chosen
      }
-- validatePerasCert unconditionally returns Right => stored in PerasCertDB
-- chainSelSync triggers chain selection for nonCanonicalBlockPoint

-- Step 2: Legitimate certificate for round 42 arrives (boosting the canonical block)
let legitimateCert = PerasCert
      { pcCertRound      = PerasRoundNo 42
      , pcCertBoostedBlock = canonicalBlockPoint
      }
-- processCerts: round 42 is already in alreadyInDb => legitimateCert is filtered out
-- implAddCert is never called for legitimateCert
-- Result: PerasCertAlreadyInDB, chain selection for canonicalBlockPoint never triggered

-- Step 3: getLatestCertSeen returns the malicious certificate
-- => voting precondition for round 43+ is satisfied using the wrong certificate
-- => node votes based on the malicious certificate's boosted block
```

The `processCerts` filter at line 166 of `PerasCert.hs` is the exact analog of the `isAccountCreated(accountId)` check in the external report: first registration wins, and the legitimate operation is permanently blocked. [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-342)
```haskell
  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L178-179)
```haskell
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L495-531)
```haskell
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-71)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
```
