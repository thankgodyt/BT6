### Title
Peras Certificate Validation Fully Bypassed — Any Peer Can Forge Certificates to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. Because this function is the sole gate used by the inbound Peras certificate diffusion mini-protocol, any unprivileged peer can send a crafted `PerasCert` claiming to boost an arbitrary block. The node accepts it, stores it in the `PerasCertDB`, and triggers chain selection with the forged boost weight applied, potentially causing the node to prefer a non-canonical adversarial chain.

---

### Finding Description

**Root cause — stub validation always succeeds**

The degenerate `BlockSupportsPeras` instance (the only active instance for all block types) implements `validatePerasCert` as:

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

No aggregate BLS signature check, no committee membership check, no quorum threshold check, and no round-number plausibility check is performed. Every certificate, regardless of content, is stamped `ValidatedPerasCert` with the full `perasWeight params` boost (default `PerasWeight 15`).

**Inbound path — peer-supplied certificates reach this stub directly**

The production inbound handler for the Peras certificate diffusion mini-protocol is wired in `NodeToNode.hs`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

`processCerts` applies this function to every new certificate from the peer and, if it returns `Right`, immediately passes the result to `addCert` (which stores it in the `PerasCertDB`): [4](#0-3) 

**Chain selection consequence**

Once stored, the certificate is processed by `chainSelSync`, which reads the boosted block from the `VolatileDB` and triggers `chainSelectionForBlock` for it: [5](#0-4) 

Chain comparison uses `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`. A forged certificate adds `PerasWeight 15` to the adversarial chain's weight: [6](#0-5) 

**Exploit flow**

1. Attacker connects to a Peras-enabled node as a normal peer.
2. Attacker sends a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = <adversarial block point>`.
3. `validatePerasCert` returns `Right` unconditionally — no signature, no committee, no quorum check.
4. The certificate is stored and chain selection fires for the adversarial block.
5. The adversarial chain now carries `+15` weight per forged certificate.
6. If the adversarial chain is within 15 blocks of the honest tip, the node switches to it.
7. The attacker can repeat with additional forged certificates to overcome larger gaps.

The `PerasCertDB` deduplicates by round number, so only one certificate per round is accepted. However, with `perasCertMaxRounds = 487` rounds in the window, an attacker can inject up to 487 forged certificates, adding up to `487 × 15 = 7305` weight units to an adversarial chain — far exceeding the honest chain's block-number-based weight in any realistic scenario. [7](#0-6) 

---

### Impact Explanation

**High — Chain selection manipulation enabling preference of a non-canonical chain.**

An unprivileged peer can cause an honest Peras-enabled node to switch to an adversarial chain by injecting forged certificates that artificially inflate the adversarial chain's Peras weight. This directly violates the Peras security model, which assumes certificates are only issued by a quorum of honest committee members. The attack bypasses the entire Peras certificate verification stack (aggregate BLS signature, VRF-based committee eligibility, quorum threshold) because the validation function is a no-op stub deployed in production code.

---

### Likelihood Explanation

**Medium.** Peras is described as disabled by default (`Note that if Peras is disabled (which is the default), there is no observable difference`), but the certificate diffusion mini-protocol handlers are unconditionally wired into the node-to-node protocol stack. Any deployment that enables Peras (e.g., private testnets, future mainnet activation) is immediately vulnerable. The attack requires only a standard peer connection and the ability to send a well-formed `PerasCert` CBOR message — no keys, no stake, no privileged access.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature against the declared voter set.
2. Checks that each declared voter is a legitimate committee member for the claimed round (VRF eligibility for non-persistent members, persistent membership for persistent members).
3. Verifies that the total stake of the declared voters meets the quorum threshold (`perasQuorumStakeThreshold`).
4. Validates that `pcCertRound` falls within the acceptable window relative to the current chain tip.

Until this is implemented, the Peras certificate diffusion mini-protocol should be disabled at the network negotiation level to prevent unauthenticated certificates from influencing chain selection.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node as a peer.
2. Negotiate the Peras certificate diffusion mini-protocol.
3. Send a `PerasCert` CBOR payload:
   - `pcCertRound`: any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock`: the `Point` of a block on an adversarial fork in the node's `VolatileDB`
4. Observe via tracing that `ChainSelectionForBoostedBlock` fires and the node switches to the adversarial fork.
5. Repeat with different round numbers (up to `perasCertMaxRounds = 487`) to accumulate up to `7305` weight units on the adversarial chain, overcoming any honest chain of fewer than 7305 blocks.

The stub at `SupportsPeras.hs:353–358` guarantees step 3 always succeeds regardless of certificate content. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L154-177)
```haskell
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
