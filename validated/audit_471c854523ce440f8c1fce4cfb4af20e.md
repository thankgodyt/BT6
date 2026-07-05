### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation, Enabling Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which applies universally to all block types including production Cardano blocks, implements `validatePerasCert` as an unconditional `Right` — accepting every inbound Peras certificate without performing any cryptographic, committee-membership, or round-validity check. Any unprivileged peer connected via the Peras ObjectDiffusion mini-protocol can inject a crafted `PerasCert` that is accepted, stored in the `PerasCertDB`, and used to artificially boost an arbitrary block's weight in chain selection. This is the direct consensus analog of the external report's `execute`/`withdrawAll` pattern: a function that is supposed to enforce authorization instead performs no check at all, granting any caller the full power of the privileged action.

---

### Finding Description

**Root cause — unconditional certificate acceptance**

The universal instance at lines 318–389 of `SupportsPeras.hs` is explicitly marked as a temporary scaffold:

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
```

No signature is verified, no committee membership is checked, no round bounds are enforced. Every `PerasCert` value — regardless of origin or content — is wrapped in `Right` and returned as a fully validated certificate carrying the full configured `perasWeight`.

**Inbound network path**

`processCerts` in `ObjectPool/PerasCert.hs` is the inbound handler for certificates received from peers over the ObjectDiffusion mini-protocol. It calls the `validateCert` callback, which resolves to `validatePerasCert`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never reached. Every certificate in the batch is accepted and forwarded to `addCert`.

**Chain selection impact**

`chainSelSync` in `ChainSel.hs` processes each accepted certificate. It adds the certificate to the `PerasCertDB`, then — if the boosted block exists in the `VolatileDB` and is newer than the immutable tip — triggers `chainSelectionForBlock` with the boosted block's header:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

Chain selection uses `WeightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost`. A forged certificate injects `perasWeight params` of artificial boost onto any attacker-chosen block, potentially making a shorter adversary fork outweigh the honest chain.

**Exploit flow**

1. Attacker connects to a target node as a normal peer (no privileged access required).
2. Attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversaryBlockPoint }` pointing to a block the attacker has already propagated into the node's `VolatileDB`.
3. Attacker sends the certificate over the Peras ObjectDiffusion mini-protocol.
4. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
5. The certificate is stored in `PerasCertDB` and `chainSelSync` triggers chain selection.
6. The adversary block now carries `perasWeight` extra weight; if this exceeds the honest chain's lead, the node switches forks.

---

### Impact Explanation

**Classification: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

When Peras is enabled, an attacker with no keys and no stake can:
- Force a target node to switch to an adversary-controlled fork by injecting a forged certificate that boosts a block on that fork.
- Repeat the attack for every new volatile block, continuously biasing chain selection away from the honest chain.
- Combine with a withheld block to cause a rollback beyond what the honest protocol would permit.

The `perasWeight` boost is additive and unbounded in the number of forged certificates an attacker can inject (subject only to the one-cert-per-round deduplication in `PerasCertDB`), so an attacker can accumulate large artificial weight advantages across multiple rounds.

---

### Likelihood Explanation

Peras is disabled by default on mainnet but is a production feature under active development and is enabled on private testnets and staging environments. The attack requires only a standard peer connection — no keys, no stake, no privileged access. The entry point (`processCerts`) is directly reachable from any connected peer when Peras is enabled. The TODO comments confirm the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check that verifies:
1. The certificate's aggregate BLS signature against the declared committee members' verification keys (using `verifyAggregateVoteSignature` from `CryptoSupportsAggregateVoteSigning`).
2. That the declared voters are registered committee members with sufficient combined stake to meet the quorum threshold.
3. That the certificate's round number is within the valid window relative to the current chain tip.

Until a real implementation is ready, the degenerate instance should either reject all certificates (`Left PerasValidationErr`) or the Peras ObjectDiffusion inbound handler should be gated behind the Peras feature flag so that no certificates are accepted when the full validation logic is absent.

---

### Proof of Concept

On a private testnet with Peras enabled:

```
-- Attacker constructs a forged certificate for any block hash H
-- already present in the target node's VolatileDB:
let forgeCert = PerasCert
      { pcCertRound      = PerasRoundNo 42          -- any round not yet in DB
      , pcCertBoostedBlock = BlockPoint slot H       -- adversary block
      }

-- Send forgeCert to the target node via the Peras ObjectDiffusion
-- mini-protocol (standard peer connection, no keys required).
--
-- processCerts calls validatePerasCert forgeCert
--   => Right (ValidatedPerasCert { vpcCert = forgeCert
--                                , vpcCertBoost = perasWeight params })
--
-- chainSelSync adds the cert to PerasCertDB and calls
-- chainSelectionForBlock for block H.
--
-- WeightedSelectView for any chain containing H now has
-- wsvTotalWeight += perasWeight params, potentially exceeding
-- the honest chain's total weight and causing a fork switch.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-87)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
