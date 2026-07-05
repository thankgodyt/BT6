Looking at the actual code, I need to trace the exact types and call paths involved.

The object diffusion protocol is fully wired into production in `NodeToNode.hs` at line 382, and the `validatePerasCert` stub is confirmed. Let me verify the chain selection weight impact.

### Title
Degenerate `validatePerasCert` stub accepts any inbound Peras certificate over the wired-up object-diffusion protocol, triggering chain selection for an adversary-chosen block — (`Ouroboros/Consensus/Block/SupportsPeras.hs`, `Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass instance unconditionally returns `Right` from `validatePerasCert` (no BLS aggregate-signature check, no quorum check, no committee-membership check). The Peras certificate object-diffusion protocol is fully wired into the production `NodeToNode` handler stack. Any peer connecting via `NodeToNodeV_16` can send a crafted `PerasCert blk` naming an arbitrary boosted block; `processCerts` will accept it, enqueue it to the ChainDB, and `chainSelSync` will call `chainSelectionForBlock` for that block with a weight boost of 15 — enough to flip chain selection to an adversary-controlled fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:** [1](#0-0) 

The comment at line 318 reads *"TODO: degenerate instance for all blks to get things to compile"* (issue #73). The implementation at lines 353–358 is:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

No BLS aggregate-signature verification, no committee-membership check, no quorum check. Every certificate passes.

**Entry point — object-diffusion protocol is wired into production `NodeToNode`:** [2](#0-1) 

`hPerasCertDiffusionClient` calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB systemTime getChainDB`. This is not gated behind a feature flag; it is active for any peer speaking `NodeToNodeV_16`.

**`processCerts` calls the stub and forwards to ChainDB:** [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validation function and `(void . ChainDB.addPerasCertAsync chainDB)` as the sink. The `processCerts` function at lines 164–173 calls `validateCert` on each inbound cert; because the stub always returns `Right`, every cert is forwarded to `addPerasCertAsync`. [4](#0-3) 

**`chainSelSync` triggers `chainSelectionForBlock` for the boosted block:** [5](#0-4) 

If the boosted block is present in the VolatileDB (line 520), `chainSelectionForBlock` is called at line 531 with the full Peras weight boost applied.

**The weight boost is 15 — a decisive chain-selection advantage:** [6](#0-5) 

`perasWeight = PerasWeight 15`. The security parameter `k` is the maximum rollback weight; a boost of 15 equals 15 blocks of weight, sufficient to flip selection to a fork that is up to 15 blocks shorter than the honest chain.

---

### Clarification on the question's framing

The question names `fromPerasCert` (in `Committee.hs`) and `V1.PerasCert` as part of the attack path. **These are not in the actual attack path.** `fromPerasCert` is a type-conversion utility used in the voting/forging path; it is never called by `processCerts`. The type diffused over the object-diffusion protocol is the degenerate `PerasCert blk` (fields: `pcCertRound`, `pcCertBoostedBlock` only — no BLS signature field), not `V1.PerasCert`. Sending a `V1.PerasCert` would fail CBOR deserialization. The actual attack constructs a bare `PerasCert blk` with an arbitrary `pcCertBoostedBlock`. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can inject a certificate naming any block in the VolatileDB. The node will apply a weight boost of 15 to that block and re-run chain selection. If the adversary's fork plus the boost outweighs the honest chain, the node irreversibly switches to the adversary-controlled fork. This satisfies:

- **Critical — Bypass of Peras certificate checks** (no BLS signature, no quorum, no committee-membership verification).
- **Critical — Consensus safety failure** (node accepts a forged certificate and may switch to a divergent chain).

---

### Likelihood Explanation

The protocol is fully wired up and active for any `NodeToNodeV_16` peer. No stake, no keys, no prior relationship required. The only precondition is that the target block must be in the VolatileDB (i.e., recently received but not yet immutable). This is trivially satisfiable: an attacker who also participates in block diffusion can ensure the target block is present.

---

### Recommendation

1. **Do not ship `NodeToNodeV_16` / the Peras cert diffusion protocol to any network (testnet or mainnet) until `validatePerasCert` performs real BLS aggregate-signature verification and committee-membership/quorum checks.** The TODO at issue #120 must be resolved before the protocol is enabled.
2. Gate `hPerasCertDiffusionClient`/`hPerasCertDiffusionServer` behind an explicit feature flag that is disabled by default until validation is complete.
3. Replace the degenerate `BlockSupportsPeras` instance (issue #73) with a proper per-era implementation before enabling the protocol.

---

### Proof of Concept

On an unmodified local node (io-sim or private testnet) with `NodeToNodeV_16`:

1. Connect as a peer.
2. Construct `PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <hash of a block in the peer's VolatileDB> }`.
3. Send it via the `perasCertDiffusionProtocol` inbound channel.
4. Observe: `processCerts` calls `validatePerasCert` → `Right`; `ChainDB.addPerasCertAsync` is called; `chainSelSync` logs `ChainSelectionForBoostedBlock`; `chainSelectionForBlock` runs for the named block with `PerasWeight 15` applied.
5. If the boosted fork's total weight exceeds the current chain's weight, the node switches chains — without any valid BLS signature ever being checked.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
