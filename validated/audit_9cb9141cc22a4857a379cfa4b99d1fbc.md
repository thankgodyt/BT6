Let me check the chain selection impact and whether Peras is actually wired into production deployment.

### Title
Stub `validatePerasCert` Unconditionally Accepts Any Inbound Peras Certificate, Enabling Unauthorized Chain-Selection Weight Boost — (`Ouroboros/Consensus/Block/SupportsPeras.hs`, `ObjectPool/PerasCert.hs`, `NodeToNode.hs`)

---

### Summary

The only production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, skipping all aggregate BLS signature, committee quorum, round validity, and boosted-block existence checks. This stub is wired directly into the production NodeToNode Peras-cert diffusion handler. An adversarial peer can send a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block already in the victim's `VolatileDB`, have it accepted without any cryptographic check, and trigger `chainSelectionForBlock` for that block with a full Peras weight boost — potentially causing the honest node to switch to an adversarial fork.

---

### Finding Description

**Root cause — stub validator:** [1](#0-0) 

The degenerate `instance StandardHash blk => BlockSupportsPeras blk` is the **only** instance in the codebase. Its `validatePerasCert` ignores the certificate entirely and returns `Right` for every input:

```haskell
-- TODO: perform actual validation …
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

**Production wiring — NodeToNode handler:** [2](#0-1) 

`hPerasCertDiffusionClient` is wired to `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB`, which passes `validatePerasCert mkPerasParams` as the cert validator: [3](#0-2) 

**Call chain — inbound to chain selection:**

1. `objectDiffusionInbound` → `opwAddObjects objectsToAck` (Inbound.hs line 408) [4](#0-3) 

2. `processCerts` calls `validateCert` (= `validatePerasCert mkPerasParams`) on each cert — always `Right`: [5](#0-4) 

3. Accepted cert is forwarded to `ChainDB.addPerasCertAsync`, which enqueues `ChainSelAddPerasCert`: [6](#0-5) 

4. `chainSelSync` looks up `pcCertBoostedBlock` in `VolatileDB`; if found, calls `chainSelectionForBlock` with the full Peras weight boost: [7](#0-6) 

---

### Impact Explanation

The Peras weight boost (`perasWeight params`) is added to the boosted block's chain weight during `chainSelectionForBlock`. If the attacker's block is on a fork that previously lost chain selection by a margin smaller than `perasWeight`, the node will switch to the adversarial fork. This constitutes:

- **Bypass of Peras certificate/signature validation** — no aggregate BLS signature, no committee quorum, no round validity check is performed.
- **Unauthorized chain-selection weight boost** — an adversarial peer can promote any block already in the `VolatileDB` (i.e., any block that passed header/body validation but lost chain selection) to the preferred chain.

The only guards in `chainSelSync` that limit scope are: the boosted block must not be older than the immutable tip, must not already be on the current chain, and must be present in the `VolatileDB`. None of these require the cert to be cryptographically valid.

---

### Likelihood Explanation

The precondition — a valid (but losing) fork block in the victim's `VolatileDB` — is routinely satisfied in any network with natural forks. The attacker only needs to be a connected peer and know the hash of any such block. The Peras cert diffusion protocol is fully wired in the production `NodeToNode` handler with no feature flag or era guard visible in the code.

---

### Recommendation

Replace the stub `validatePerasCert` with real validation before the Peras cert diffusion protocol is enabled in any deployment. At minimum, the validator must check:

1. Aggregate BLS signature over the claimed committee members' votes.
2. Committee quorum threshold for the claimed round.
3. Round validity (cert round within the current Peras window).
4. Boosted block existence and eligibility per the Peras protocol rules.

The TODO tracking this is [tweag/cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120). Until real validation is wired in, the Peras cert diffusion miniprotocol must not be negotiated with untrusted peers.

---

### Proof of Concept

On an unmodified local testnet (io-sim or private network):

1. Start a node with the Peras cert diffusion handler active.
2. Arrange for a valid but losing fork block `B_adv` to be present in the victim's `VolatileDB` (e.g., by briefly connecting a block-producing peer on a fork).
3. From an adversarial peer, send a `PerasCert` message with `pcCertBoostedBlock = point(B_adv)` and any `pcCertRound`.
4. Observe that `processCerts` accepts the cert (no exception thrown), `chainSelSync` finds `B_adv` in `VolatileDB`, and `chainSelectionForBlock` is invoked for `B_adv`.
5. If `perasWeight` exceeds the honest chain's lead, the node switches to the adversarial fork — confirming unauthorized certificate acceptance and chain-selection manipulation.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/Inbound.hs (L407-409)
```haskell

        opwAddObjects objectsToAck
        traceWith tracer $
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L519-531)
```haskell
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
