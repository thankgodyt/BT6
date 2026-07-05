### Title
Peras Certificate Validation Bypass via Unconditionally-Accepting `validatePerasCert` Stub — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The default `BlockSupportsPeras` instance supplies a `validatePerasCert` that unconditionally returns `Right`, accepting every inbound Peras certificate with no cryptographic, eligibility, or quorum check. The live `PerasCertDiffusion` mini-protocol handler in `NodeToNode.hs` routes every peer-supplied certificate through this stub. An unprivileged peer can therefore inject a crafted certificate that boosts any block already in the victim node's VolatileDB, triggering chain selection and causing the node to prefer a non-canonical chain.

### Finding Description

The root cause is the default method body in `BlockSupportsPeras`:

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

A grep for `validatePerasCert` across the entire repository returns exactly two files: `SupportsPeras.hs` (definition + default body) and `PerasCert.hs` (call site). No concrete `BlockSupportsPeras` instance for `CardanoBlock` or any era block overrides this default. Every certificate received from a peer is therefore unconditionally promoted to a `ValidatedPerasCert` carrying the full `perasWeight` boost.

The live call path is:

1. `NodeToNode.hs` wires `hPerasCertDiffusionClient` to `makePerasCertPoolWriterFromChainDB`: [2](#0-1) 

2. `makePerasCertPoolWriterFromChainDB` (in `PerasCert.hs`) calls `validatePerasCert` for each inbound certificate. Because it always returns `Right`, the certificate is stored via `ChainDB.addPerasCertAsync`.

3. `ChainSel.hs` (`chainSelSync` / `ChainSelAddPerasCert`) triggers chain selection for the block named in `pcCertBoostedBlock`, if that block is present in the VolatileDB: [3](#0-2) 

4. Chain selection uses `WeightedSelectView` / `wsvTotalWeight`, which adds `PerasWeight` to `BlockNo`. The boosted chain may now be preferred: [4](#0-3) 

A secondary stub, `getPerasCertInBlock _ = Nothing`, means no certificates are ever extracted from on-chain blocks, so the `PerasCertDB` is populated exclusively via the diffusion protocol — the only path that calls `validatePerasCert`. [5](#0-4) 

The companion issue — `makePerasVotePoolWriterFromChainDB` called with `pure (PerasVoteStakeDistr mempty)` causing all votes to be rejected — is a harmless-rejection / DoS-class issue and is separately disqualified: [6](#0-5) 

### Impact Explanation

An unprivileged peer learns a recent block hash `H` from the victim's VolatileDB via the ChainSync mini-protocol. It constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s H }` for any round `r` and slot `s`, and sends it via the `PerasCertDiffusion` mini-protocol. The victim accepts it without signature, eligibility, or quorum verification, stores it, and re-runs chain selection. The chain ending at `H` now carries extra `PerasWeight`; if it is otherwise competitive, the victim switches to it, diverging from the honest majority chain.

This matches the **High** impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

The `PerasCertDiffusion` handler is wired unconditionally in `NodeToNode.hs`. Whether the protocol is actually negotiated depends on the `PerasSupport` flag resolved in `Node.hs` (6 matches, not fully inspected). On any private testnet or staging environment where Peras diffusion is enabled — the explicit scope of this audit — every connected peer is a potential attacker with zero prerequisites. Likelihood is **Medium** for private-testnet / pre-production deployments where Peras is being exercised.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's aggregate BLS signature against the claimed committee members.
- That the signers were eligible committee members for the stated round (using `VotingCommittee` / `WFALS` eligibility checks already present in `Committee/WFALS.hs`).
- That the aggregate stake meets `PerasQuorumStakeThreshold`.

As an immediate mitigation, change the default body to `Left PerasValidationErr` (reject all) until the real implementation is in place. This mirrors the safe-by-default posture already used for `validatePerasVote` when the stake distribution is unavailable.

### Proof of Concept

On a private testnet with Peras diffusion enabled:

1. Attacker connects to victim and learns block hash `H` via ChainSync.
2. Attacker constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s H }`.
3. Attacker sends the certificate via the `PerasCertDiffusion` mini-protocol.
4. Victim calls `validatePerasCert`; receives `Right (ValidatedPerasCert { vpcCertBoost = perasWeight params })` unconditionally.
5. Victim stores the certificate and re-runs chain selection; the chain ending at `H` now carries extra `PerasWeight`.
6. If the boosted chain is otherwise competitive, the victim switches to it, diverging from the honest majority chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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
