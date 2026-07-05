### Title
Unconditional `validatePerasCert` Acceptance Enables Forged-Certificate Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` provides a `validatePerasCert` implementation that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. Because the Peras certificate diffusion miniprotocol feeds received certificates directly through this function before storing them in the `PerasCertDB` and triggering chain selection, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub used in production**

The only `BlockSupportsPeras` instance in the codebase is the catch-all degenerate instance:

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
``` [1](#0-0) 

The `PerasCert` data type in this instance carries only a round number and a block point — no aggregate signature, no voter bitmap, no VRF outputs:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

There is literally nothing to verify cryptographically, and the function does not attempt to do so.

**Production call path — network handler → `validatePerasCert` → ChainDB**

The Peras certificate diffusion inbound handler in `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` directly as the validation function for every batch of certificates received from a peer:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    -- TODO replace when actual plumbing is in place
    (validatePerasCert mkPerasParams)
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [3](#0-2) 

`processCerts` partitions the results of `validateCert` and, if all pass (which they always do), timestamps and stores each certificate: [4](#0-3) 

This pool writer is wired into the NodeToNode handler:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [5](#0-4) 

**Chain selection impact — accepted cert triggers weight-boosted chain selection**

Once a certificate is stored in the `PerasCertDB`, `chainSelSync` is called for the boosted block:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

Chain comparison uses `preferAnchoredCandidate`, which, when the `PerasWeightSnapshot` is non-empty, computes `weightBoostOfFragment` and compares `wsvTotalWeight = blockNo + weightBoost`:

```haskell
case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
  LT -> ShouldSwitch (Heavier $ ...)
  ...
``` [7](#0-6) 

A forged certificate with `vpcCertBoost = perasWeight params` (the configured Peras weight, e.g. 15 blocks worth of weight) is indistinguishable from a legitimate one, so the honest node will switch to the attacker's chain if it is otherwise equal or close in length.

**Analog to the external report**

| External report | This finding |
|---|---|
| `position.owner == msg.sender` check prevents self-liquidation | `validatePerasCert` is supposed to verify a quorum of committee signatures |
| Bypassed by routing through a proxy contract so `msg.sender ≠ owner` | Bypassed trivially — the check is entirely absent; the function always returns `Right` |
| Attacker atomically creates unhealthy position and self-liquidates | Attacker sends a crafted cert naming any block; honest node boosts that block in chain selection |
| Lenders bear the loss | Honest nodes are steered onto the attacker's chain |

---

### Impact Explanation

**High — chain selection manipulation via forged Peras certificates.**

An unprivileged peer can cause an honest node to prefer a non-canonical chain by injecting a certificate that boosts a block on the attacker's fork. The boost weight is additive with block number, so a short attacker fork can be made to appear heavier than the honest chain. This violates the chain-selection invariant that only legitimately certified blocks receive weight boosts, and can result in honest nodes permanently adopting an adversarial chain segment.

---

### Likelihood Explanation

**Medium-High.** The attack requires only a standard peer connection — no stake, no keys, no privileged access. The attacker needs to know the hash of a block they want to boost (public information from the chain). The only limiting factor is that Peras is currently disabled by default; however, the diffusion handlers and validation path are fully wired and active whenever Peras is enabled (including private testnets or future mainnet activation). The `validatePerasCert` stub is the only instance in the codebase, so there is no fallback to a correct implementation.

---

### Recommendation

1. **Implement real cryptographic validation in `validatePerasCert`** before enabling Peras on any network. The `PerasCert` data type must carry an aggregate BLS signature (as already done in `Ouroboros.Consensus.Peras.Cert.V1.PerasCert`) and the validation function must verify it against the committee's public keys and the claimed voter set.

2. **Gate the diffusion handler on Peras being enabled.** Until a real `validatePerasCert` is in place, the inbound cert diffusion handler should reject all certificates (return `Left`) rather than accept them unconditionally.

3. **Remove the catch-all `instance StandardHash blk => BlockSupportsPeras blk`** once era-specific instances exist, to prevent the stub from silently being used for any new block type.

---

### Proof of Concept

A malicious peer connects to a Peras-enabled node and sends a single `PerasCert` message over the Peras certificate diffusion miniprotocol:

```
PerasCert
  { pcCertRound     = <any round not yet in the DB>
  , pcCertBoostedBlock = <Point of a block on the attacker's fork>
  }
```

**Expected (correct) behavior:** `validatePerasCert` rejects the certificate because no aggregate committee signature is present or the signature does not verify.

**Actual behavior:** `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally. `processCerts` stores the certificate. `chainSelSync` triggers chain selection for the boosted block. `preferAnchoredCandidate` now computes a higher `wsvTotalWeight` for the attacker's fork (block number + boost weight), and the honest node switches to the attacker's chain.

The attack is repeatable across rounds (each round has a distinct `pcCertRound`), allowing the attacker to continuously steer the honest node's selection.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
