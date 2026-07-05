### Title
`validatePerasCert` stub unconditionally accepts all inbound Peras certificates, enabling chain-selection manipulation by any unprivileged peer — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives. Because `processCerts` relies entirely on this function as its only content-level gate, any unprivileged peer can inject crafted `PerasCert` objects for arbitrary round numbers. Each accepted certificate is forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection for the attacker-chosen boosted block. The analog to the external report is exact: just as `distributeRewards` lacked a time-based guard and could be called repeatedly to accumulate excessive state, `validatePerasCert` lacks any guard at all and allows a peer to inject certificates for any round, repeatedly manipulating chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The only `BlockSupportsPeras` instance in the codebase is the degenerate catch-all instance. Its `validatePerasCert` method ignores every field of the certificate and always returns `Right`:

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

No round-number range check, no BLS/committee signature check, no boosted-block existence check — the function is a pure identity wrapper.

**Inbound pipeline — `processCerts` relies solely on this stub:**

`processCerts` deduplicates by round number (one cert per round already in DB is skipped), then calls `validateCert` on the remainder. Because `validateCert` is always `Right`, every cert for a round not yet in the DB is accepted unconditionally:

```haskell
let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
...
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [2](#0-1) 

The production writer path passes `validatePerasCert mkPerasParams` directly as the `validateCert` argument and then calls `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection consequence — `addPerasCertAsync` triggers fork evaluation:**

`addPerasCertAsync` enqueues the certificate on `cdbChainSelQueue`. `chainSelSync` then processes it: if the boosted block is in the VolatileDB and not already on the current chain, `chainSelectionForBlock` is called, potentially switching the node to a fork:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The only existing guard is that the boosted block must not be older than the immutable tip — blocks in the VolatileDB (the volatile suffix) are fully eligible. [5](#0-4) 

**Contributing factor — `validatePerasVote` also skips cryptographic checks:**

The same degenerate instance's `validatePerasVote` only checks stake-distribution membership; it does not verify the BLS signature or VRF eligibility proof. A peer who knows the public stake distribution (which is on-chain) can forge votes for any eligible voter, accumulate quorum, and trigger certificate generation internally — compounding the cert-injection path. [6](#0-5) 

The `implAddVote` implementation itself carries an explicit TODO acknowledging the missing validation: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash in the node's VolatileDB as the boosted block and any round number not yet in the `PerasCertDB`. The certificate passes `validatePerasCert` unconditionally, is stored, and triggers `chainSelectionForBlock` for the attacker-chosen block. If the Peras weight boost makes that fork heavier than the current selection, the node switches chains — accepting a non-canonical or adversarially chosen chain. This directly matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a standard peer-to-peer channel reachable by any connecting node. No key material, operator access, or stake majority is required. The attacker only needs to know a block hash present in the target node's VolatileDB (obtainable via ChainSync) and to send a single well-formed CBOR-encoded `PerasCert` for a round not yet in the DB. The degenerate `BlockSupportsPeras` instance is the only instance in the repository and is used in all current builds.

---

### Recommendation

1. Implement real certificate validation in `validatePerasCert`: verify the aggregated BLS signature over `(roundNo, boostedBlock)` against the committee's aggregate public key, and confirm the round number falls within the current or recent window.
2. Implement real vote validation in `validatePerasVote`: verify the BLS signature and, for non-persistent members, the VRF eligibility proof.
3. Add a round-range guard in `processCerts` (analogous to the time-based guard recommended in the external report): reject certificates whose round number is outside `[currentRound - maxLookback, currentRound + maxLookahead]`.
4. Track the issue already filed at `https://github.com/tweag/cardano-peras/issues/120` and treat it as a security-critical blocker before any Peras-enabled deployment.

---

### Proof of Concept

Attacker steps (no special privileges):

1. Connect to the target node via the ObjectDiffusion mini-protocol for Peras certificates.
2. Obtain a block hash `h` from the node's VolatileDB via ChainSync (any recent non-selected fork block).
3. Construct a `PerasCert` with `pcCertRound = <any round not yet in DB>` and `pcCertBoostedBlock = h`.
4. Send the certificate batch to the node.
5. `processCerts` filters out nothing (round not in DB), calls `validatePerasCert` → `Right`.
6. `addCert` → `ChainDB.addPerasCertAsync` → `chainSelSync (ChainSelAddPerasCert ...)`.
7. `chainSelectionForBlock` is called for block `h`; if the Peras boost makes the fork heavier, the node switches to the attacker-chosen chain.

Repeat with different round numbers to inject multiple certificates boosting the same or different fork blocks, since the only deduplication is per-round.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L487-492)
```haskell
  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
