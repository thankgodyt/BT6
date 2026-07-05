### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance used for all block types contains a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing no cryptographic, committee-membership, or quorum verification. An unprivileged peer can send a crafted `PerasCert` for any block already in the node's VolatileDB, causing the node to apply a weight boost to that block and trigger chain selection, potentially switching the node to a non-canonical fork.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is stored and used to influence chain selection. The degenerate instance that covers **all** block types (including production Cardano blocks) is:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
``` [1](#0-0) 

This stub is wired directly into the production inbound-certificate path via `makePerasCertPoolWriterFromChainDB`, which is the writer used when certificates arrive from peers over the network:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls this validator and, if it returns `Right`, immediately timestamps and forwards the certificate to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`chainSelSync` then processes the certificate: it adds it to the `PerasCertDB`, updates the `PerasWeightSnapshot`, and calls `chainSelectionForBlock` for the boosted block: [4](#0-3) 

Chain selection computes total weight as `blockNo + weightBoost` via `wsvTotalWeight` and `preferCandidate`: [5](#0-4) 

The `SecurityParam` documentation explicitly states that in Peras, `k` is the **maximum weight** that can be rolled back, not just the maximum block count: [6](#0-5) 

### Impact Explanation

An unprivileged peer can send a `PerasCert` pointing to any block already in the victim node's VolatileDB. Because `validatePerasCert` always returns `Right`, the certificate is accepted without any verification of:
- Cryptographic proof of committee votes
- Committee membership eligibility
- Quorum threshold being met
- Round number validity

The accepted certificate assigns a boost of `perasWeight mkPerasParams = PerasWeight 15` to the targeted block. With `wsvTotalWeight = blockNo + weightBoost`, a fork that is up to 14 blocks shorter than the current honest chain tip can be made to appear heavier and be selected. This constitutes a bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-weight manipulation, matching the **Critical** impact class: bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance.

### Likelihood Explanation

The Peras certificate object-diffusion mini-protocol is active in the production codebase and accepts inbound certificates from any connected peer. No stake, key material, or special privilege is required — any peer that can connect to the node can send a crafted `PerasCert`. The only prerequisite is that the targeted block is already in the node's VolatileDB, which is the normal state during chain sync. Likelihood is **High**.

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that:
1. Verifies the cryptographic proof of committee votes (VRF/KES signatures from committee members).
2. Checks that the voter set meets the quorum threshold (`stakeAboveThreshold`).
3. Validates committee membership against the current stake distribution.
4. Checks that the certificate's `vpcCertBoost` does not exceed `maxRollbackWeight secParam`.

Until real validation is implemented, the inbound certificate path in `makePerasCertPoolWriterFromChainDB` should reject all externally received certificates (i.e., treat the stub as always returning `Left`), preventing any peer from influencing chain selection via Peras weight boosts.

### Proof of Concept

1. Attacker connects to a victim node as a peer via the Peras certificate mini-protocol.
2. Attacker observes a block `B` on a minority fork that is already in the victim's VolatileDB (received via normal BlockFetch).
3. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B }`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
5. Certificate is forwarded to `ChainDB.addPerasCertAsync`.
6. `chainSelSync` adds it to `PerasCertDB`, updates `PerasWeightSnapshot` with `+15` for block `B`.
7. `chainSelectionForBlock` is called for `B`; `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork containing `B` as `blockNo(B) + 15`.
8. If the honest chain tip has `blockNo ≤ blockNo(B) + 14`, the adversarial fork is now preferred and the node switches to it — a chain selection manipulation triggered entirely by an unauthenticated network message. [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-44)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
newtype SecurityParam = SecurityParam {maxRollbacks :: NonZero Word64}
  deriving (Eq, Generic, NoThunks, ToCBOR, FromCBOR)
  deriving Show via Quiet SecurityParam

-- | The maximum amount of weight we can roll back.
maxRollbackWeight :: SecurityParam -> PerasWeight
maxRollbackWeight = PerasWeight . unNonZero . maxRollbacks
```
