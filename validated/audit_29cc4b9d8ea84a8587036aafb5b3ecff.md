### Title
Unconditional Peras Certificate Acceptance Bypasses Quorum Validation, Enabling Unauthorized Chain Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the degenerate `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or quorum-based validation. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, which the node will accept, store in the `PerasCertDB`, and use to boost that block's chain-selection weight by `perasWeight = 15` slots, potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must verify a certificate before it is stored and acted upon. The production instance (the only instance in the codebase, explicitly labelled a "degenerate instance for all blks to get things to compile") implements this gate as an unconditional `Right`:

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

No check is performed on:
- The aggregate BLS signature over the round identifier and boosted block hash
- Whether the signers were actually elected to the voting committee for that round
- Whether the signers' combined stake meets the quorum threshold (`perasQuorumStakeThreshold = 3/4 + 2/100`)
- Whether the certificate's round number is plausible given the current chain tip

This stub is wired directly into the inbound certificate processing pipeline. `makePerasCertPoolWriterFromChainDB` (the production path) calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions results into errors and successes; because `validatePerasCert` always returns `Right`, every certificate lands in the success bucket and is passed to `addCert`: [3](#0-2) 

Once stored, `chainSelSync` processes the certificate: it adds it to `PerasCertDB`, then calls `chainSelectionForBlock` for the boosted block, giving it `perasWeight = 15` extra slots of chain weight: [4](#0-3) 

The quorum threshold and safety margin are defined but are only consulted during local vote aggregation (`stakeAboveThreshold`), never during certificate ingestion from peers: [5](#0-4) 

The analog to the external report is exact: just as `voting_supply` was tracked but never consulted before applying governance results, `perasQuorumStakeThreshold` is defined and used locally but is never consulted when a certificate arrives from the network.

---

### Impact Explanation

A single unprivileged peer can send a `PerasCert` for any block present in the victim node's `VolatileDB`. The certificate is accepted unconditionally, stored, and immediately used to re-run chain selection with the boosted block receiving `+15` slots of weight. If the adversary's target block is on a fork that is currently losing by fewer than 15 slots of chain weight, the node will switch to that fork. This constitutes:

- **Bypass of Peras certificate/quorum checks** enabling unauthorized certificate acceptance.
- **Chain-selection manipulation** allowing an unprivileged peer to make an honest node prefer a non-canonical chain, violating the Peras safety guarantee that only a quorum-backed certificate may boost a block.

Impact: **Critical** — matches "Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance" and "chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a standard node-to-node path; any connected peer can submit certificates. The `PerasCert` type contains only a round number and a block point — both trivially constructable without any key material. No rate limiting, proof-of-work, or stake check stands between a peer and the `validatePerasCert` call. Likelihood is **High** once Peras is enabled on a live network.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that:

1. Verifies the aggregate BLS signature over `(roundNo, boostedBlock)` against the public keys of the claimed signers.
2. Confirms each signer was a member of the elected voting committee for the given round (persistent or non-persistent seat, verified via VRF output).
3. Sums the stake weights of verified signers and checks `stakeAboveThreshold params totalStake` before returning `Right`.

Until the full cryptographic plumbing is in place, the node should not expose the Peras certificate ingestion path to untrusted peers (i.e., keep Peras disabled in production, which the CHANGELOG notes is the current default).

---

### Proof of Concept

**Setup:** A private two-node testnet with Peras enabled. Node A is the honest victim; Node B is the adversary.

1. Node A and B share a common chain up to block `B_common`. Node B mines a fork starting at `B_common`, producing block `B_fork` that is currently 10 slots shorter than Node A's canonical tip `B_honest`.

2. Node B constructs a `PerasCert` with no valid signature:
   ```haskell
   craftedCert = PerasCert
     { pcCertRound      = PerasRoundNo 1
     , pcCertBoostedBlock = blockPoint B_fork
     }
   ```

3. Node B sends this certificate to Node A via the Peras cert diffusion mini-protocol.

4. On Node A, `processCerts` calls `validatePerasCert mkPerasParams craftedCert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })` unconditionally. [6](#0-5) 

5. The certificate is stored in `PerasCertDB` and `chainSelSync` triggers `chainSelectionForBlock` for `B_fork` with `+15` weight. [7](#0-6) 

6. Node A's chain selection now sees `B_fork`'s weighted length as `(length of fork) + 15`, which exceeds `B_honest`'s unweighted length of `(length of fork) + 10`. Node A switches to the adversary's fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
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
    pure $ addedCertRes
```
