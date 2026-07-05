### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — the **only** instance in the codebase, used for all block types — implements `validatePerasCert` as a stub that unconditionally returns `Right` without performing any cryptographic or structural validation. Because this stub is wired directly into the production certificate ingest path (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can send a crafted `PerasCert` message that is accepted without verification, stored in the `PerasCertDB`, and used to boost an arbitrary block's weight in chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must reject invalid certificates before they enter the node's state. The sole concrete instance, marked explicitly as a TODO stub, bypasses this gate entirely:

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

This instance is the **only** instance — it is declared as a universal `instance StandardHash blk => BlockSupportsPeras blk`, covering every block type in the system. [2](#0-1) 

The production certificate ingest path, `makePerasCertPoolWriterFromChainDB`, passes this stub directly as the validator for all inbound peer certificates:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each certificate and adds all that return `Right` — which is every certificate, regardless of content: [4](#0-3) 

Once accepted, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which triggers `chainSelSync`. That function adds the certificate to the `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection computes `wsvTotalWeight = blockNo + weightBoost`, where `weightBoost` is the sum of all `vpcCertBoost` values for blocks on the fragment. Each injected certificate contributes `perasWeight = PerasWeight 15` (from `mkPerasParams`) to the boosted block's weight: [6](#0-5) [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block in the volatile DB. Because `validatePerasCert` never rejects anything, the certificate is stored and its `PerasWeight 15` boost is applied to that block during chain selection. By injecting one certificate per round for a target fork block, an attacker can accumulate enough artificial weight to make an honest node's chain selection prefer a non-canonical, adversarially-controlled fork over the honest chain. This directly undermines the Peras security assumption that only legitimately quorum-certified blocks receive boosts.

This maps to: **High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions**, and also to **Critical — bypass of Peras certificate checks that enables unauthorized certificate acceptance**.

---

### Likelihood Explanation

The attack requires only that the Peras certificate diffusion mini-protocol is active (which it is by design in any Peras-enabled deployment) and that the attacker can connect as a peer. No stake, keys, or privileged access are needed. The attacker simply sends a well-formed CBOR-encoded `PerasCert` with a chosen `pcCertRound` and `pcCertBoostedBlock`. The only existing guard is a deduplication check on `pcCertRound` (one cert per round number), but an attacker can use a fresh round number for each injection.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic and structural validation before the Peras certificate diffusion path is enabled in any production deployment. Specifically:

1. Verify the certificate's aggregate signature against the voting committee for the relevant epoch using `verifyCert` from `CryptoSupportsVotingCommittee`.
2. Verify that the `pcCertBoostedBlock` corresponds to a real block that was eligible for boosting (age ≥ `perasBlockMinSlots`, round within `perasCertMaxRounds`).
3. Verify that the certificate's round number is within the valid acceptance window.
4. Complete the `getVotingCommitteeForElection` stub in `AcrossEpochs.hs` (currently `error "TODO: implement getVotingCommitteeForElection"`) which is a prerequisite for cross-epoch certificate validation. [8](#0-7) 

---

### Proof of Concept

On a private testnet with Peras certificate diffusion enabled:

1. Connect a malicious peer to an honest node.
2. Identify a fork block `B_fork` in the honest node's volatile DB (e.g., via the ChainSync protocol).
3. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = blockPoint B_fork`.
4. Send the certificate via the Peras object diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
6. `ChainDB.addPerasCertAsync` stores the cert; `chainSelSync` triggers chain selection for `B_fork`.
7. The fork's `wsvTotalWeight` is now `blockNo(B_fork) + 15`, potentially exceeding the honest chain's weight.
8. Repeat with fresh round numbers to accumulate additional boost (15 per injection) until the fork is preferred.

The honest node switches to the adversarial fork without any legitimate quorum having been reached.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L68-74)
```haskell
-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```
