### Title
Unconditional Peras Certificate Acceptance Bypasses All Validation, Enabling Unprivileged Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound Peras certificate, performing zero cryptographic or semantic checks. Because this is the only instance wired into the production inbound-certificate diffusion path, any unprivileged peer can inject an arbitrary `PerasCert` that boosts any block of their choosing. The boosted block then participates in chain selection with a weight advantage of `perasWeight` (15 blocks), potentially causing an honest node to prefer a non-canonical fork.

---

### Finding Description

**Root cause — stub `validatePerasCert` always succeeds:** [1](#0-0) 

The universal instance `instance StandardHash blk => BlockSupportsPeras blk` is the only `BlockSupportsPeras` instance in the codebase. Its `validatePerasCert` implementation is:

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

No committee membership check, no aggregate BLS signature verification, no quorum threshold check, no round-number bounds check — the function returns `Right` for every input unconditionally.

**Production inbound path wires this stub directly:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate and, when all pass (which they always do), forwards them to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain selection acts on the accepted certificate:**

`chainSelSync` processes the queued certificate, looks up the boosted block in the VolatileDB, and calls `chainSelectionForBlock` for it — potentially switching the node's preferred chain: [4](#0-3) 

The concrete weight applied is `perasWeight = 15` (equivalent to 15 extra blocks of chain length): [5](#0-4) 

**The real certificate type carries a full BLS aggregate signature and voter set that are never verified:** [6](#0-5) 

The `EveryoneVotes` and `WFALS` committee implementations do perform proper aggregate-signature and VRF verification in `verifyCert`: [7](#0-6) 

But `validatePerasCert` — the function called on the inbound network path — never invokes any of that logic.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and any round number, send it over the Peras certificate diffusion mini-protocol, and have it unconditionally accepted and stored. The certificate then grants the targeted block a `+15`-block weight boost in chain selection. If the attacker targets a block on a weaker fork (e.g., one that is up to 15 blocks shorter than the honest chain), the local node will switch to that fork, diverging from the canonical chain. This is a **High** impact chain-selection manipulation: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a peer-facing network endpoint. Any connected peer — including an adversarial one with no stake and no keys — can send a `PerasCert` message. The attacker needs only to know the hash of a block on a weaker fork (publicly observable from the chain) and to be connected to the target node. No key material, no stake, and no special privileges are required. The attack is deterministic and repeatable.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature against the claimed voter set and the `(roundNo, boostedBlock)` message.
2. Checks that each claimed voter is a registered committee member with non-zero stake.
3. Verifies VRF outputs for non-persistent voters.
4. Confirms the total stake of signers meets the quorum threshold (`perasQuorumStakeThreshold`).
5. Checks that the certificate's round number is within the valid window.

The `verifyCert` implementations in `EveryoneVotes` and `WFALS` already contain the correct logic and should be used as the basis for the production `validatePerasCert` implementation. The `TODO` at `https://github.com/tweag/cardano-peras/issues/120` tracks this work and must be resolved before the Peras diffusion path is exposed to untrusted peers.

---

### Proof of Concept

1. Connect to a target node that has the Peras certificate diffusion mini-protocol enabled.
2. Observe a block `B_weak` on a fork that is up to 15 blocks shorter than the node's current chain tip.
3. Craft a `PerasCert` with `pcCertRound = <any round>`, `pcCertBoostedBlock = <point of B_weak>`, `pcVoters = <empty or arbitrary>`, `pcSignature = <zeroed bytes>`.
4. Send the crafted certificate via the object-diffusion mini-protocol.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
6. The certificate is enqueued via `ChainDB.addPerasCertAsync`.
7. `chainSelSync` processes it: `B_weak` now has `+15` weight; if the fork was within 15 blocks of the honest tip, `chainSelectionForBlock` switches the node to the weaker fork.
8. The node has diverged from the canonical chain without the attacker possessing any keys or stake.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```
