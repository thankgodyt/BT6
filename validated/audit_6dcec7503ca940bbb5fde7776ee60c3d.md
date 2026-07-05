### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or structural validation whatsoever. Any unprivileged peer can send a crafted `PerasCert` through the Peras certificate object-diffusion mini-protocol; the certificate will pass the inbound validation gate, be stored in the `PerasCertDB`, and trigger chain selection for the attacker-chosen boosted block. This allows an adversary to inject artificial Peras boost weight onto any block in the node's VolatileDB, potentially causing the node to switch to a non-canonical fork.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

In the degenerate `BlockSupportsPeras` instance (the only production instance), `validatePerasCert` is explicitly marked TODO and unconditionally returns `Right`:

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

No signature, quorum proof, committee membership, or round-number plausibility check is performed. Every `PerasCert` value, regardless of content, is wrapped in `ValidatedPerasCert` and returned as valid.

**Inbound path — peer-supplied certificates reach `validatePerasCert`:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` directly as the validation callback for all inbound certificates received from peers:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    -- TODO replace when actual plumbing is in place
    (validatePerasCert mkPerasParams)
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on each certificate not already in the DB; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection consequence — injected certificate triggers fork switch:**

`chainSelSync` processes the queued certificate: it adds it to `PerasCertDB` and, if the boosted block is in the VolatileDB, immediately calls `chainSelectionForBlock` for that block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The `PerasWeightSnapshot` returned by `getWeightSnapshot` now includes the attacker-injected boost for the chosen block, which is used during chain comparison to prefer the boosted fork over the honest chain. [5](#0-4) 

**Analog to the external report:** Just as `ownershipChange` in VotingEscrow was only set in `_transferFrom` and not in split/merge, leaving alternative paths unguarded, `validatePerasCert` is called in the inbound path but performs no actual check — the "guard" is structurally present but functionally absent, allowing any peer to bypass it by simply sending a well-formed CBOR-encoded `PerasCert` with an arbitrary `pcCertBoostedBlock`.

### Impact Explanation

**High — chain selection manipulation by an unprivileged peer.**

An attacker with a single honest peer connection can inject a `PerasCert` that boosts any block hash present in the target node's VolatileDB. The injected certificate is stored in `PerasCertDB` and its boost weight is applied during chain selection, potentially causing the node to switch from the honest canonical chain to an attacker-chosen fork. Because the `PerasWeightSnapshot` persists across chain selection rounds, the effect is durable until the certificate is garbage-collected. This satisfies the "High" impact criterion: a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation

**High.** The attack requires only a peer connection and the ability to send a valid CBOR-serialised `PerasCert` message. No keys, stake, or privileged access are needed. The Peras certificate object-diffusion mini-protocol is a standard peer-facing interface. The stub is the only production instance of `BlockSupportsPeras`, so every node running this code is affected.

### Recommendation

1. Implement real cryptographic validation in `validatePerasCert`: verify the aggregate BLS signature against the claimed committee members, check that the voter set meets the quorum threshold, and validate that the round number and boosted block are plausible given the current ledger state.
2. Until the full implementation is ready, gate the inbound certificate path behind a feature flag or reject all externally supplied certificates at the mini-protocol handler level, rather than passing them through a stub validator.
3. Apply the same fix to `validatePerasVote`, which similarly omits signature verification and only checks stake-distribution membership. [6](#0-5) 

### Proof of Concept

1. Connect to a target node running this codebase via the Peras certificate object-diffusion mini-protocol.
2. Observe the VolatileDB tip hash `H` of a fork block the attacker wishes to boost (obtainable via the chain-sync mini-protocol).
3. Craft a `PerasCert` with `pcCertRound = <any round not yet in the DB>` and `pcCertBoostedBlock = <Point H>`.
4. Send the certificate to the target node. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is enqueued via `ChainDB.addPerasCertAsync`.
6. `chainSelSync` adds it to `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block.
7. The node's chain selection now treats the fork block as carrying Peras boost weight; if the fork is otherwise competitive, the node switches to it.

Expected outcome: the target node adopts the attacker-chosen fork without any legitimate quorum of committee members having voted for it.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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
