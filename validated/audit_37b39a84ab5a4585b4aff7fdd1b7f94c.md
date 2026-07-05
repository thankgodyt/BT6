### Title
Unconditional Peras Certificate Acceptance Bypasses All Signature and Quorum Validation, Enabling Peer-Injected Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound `PerasCert` as a `ValidatedPerasCert` without verifying the aggregate vote signature, voter committee eligibility, or quorum threshold. Any unprivileged peer that can send a `PerasCert` message over the Peras certificate diffusion mini-protocol can inject a certificate for an arbitrary block, causing the receiving node to apply a full `perasWeight` boost to that block during chain selection and potentially switch to an adversarially chosen fork.

---

### Finding Description

`validatePerasCert` in the default `BlockSupportsPeras` instance is a stub that always returns `Right`:

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

The function takes the peer-supplied `PerasCert` verbatim and wraps it in `ValidatedPerasCert` with the full configured `perasWeight` boost (default: 15), performing zero cryptographic or stake-based checks. The three checks that must be present — aggregate BLS/vote signature verification, committee membership and eligibility verification, and quorum stake threshold check — are all absent.

The resulting `ValidatedPerasCert` is accepted by `addPerasCertAsync` into the `PerasCertDB` and immediately triggers chain selection:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [2](#0-1) 

Chain selection then computes `wsvTotalWeight` as `blockNo + wsvWeightBoost`, where `wsvWeightBoost` is the sum of all `vpcCertBoost` values for blocks on the candidate fragment:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [3](#0-2) 

A candidate chain carrying a peer-injected fake certificate for a fork block gains `perasWeight = 15` extra weight units, which can make it preferred over the honest chain.

The `PerasVoteStakeDistr` used for vote validation is separately hardcoded to `mempty` in the production node-to-node handler, meaning all individual votes are rejected:

```haskell
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [4](#0-3) 

However, certificates received directly via the Peras certificate diffusion mini-protocol bypass this protection entirely because `validatePerasCert` never checks the underlying votes or their aggregate signature.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash and round number, send it over the Peras certificate diffusion mini-protocol, and cause the receiving node to:

1. Accept the certificate unconditionally into the `PerasCertDB`.
2. Apply a `perasWeight` boost (15 by default) to the named block in `weightedSelectView`.
3. Re-run chain selection for the boosted block, potentially switching to an adversarial fork.

The `preferCandidate` logic in `WeightedSelectView` compares `wsvTotalWeight` values:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
``` [5](#0-4) 

A fork that is 15 blocks shorter than the honest chain can be made to appear heavier by injecting a single fake certificate. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of Ouroboros Praos/Peras.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active in the production node-to-node handler (the `cPerasCertDiffusionCodec` is wired up in `defaultCodecs`). Any peer that can establish a node-to-node connection — which requires no credentials — can send a `PerasCert` message. The stub `validatePerasCert` is the only validation gate between the network and the `PerasCertDB`. The TODO comment and linked GitHub issue (`tweag/cardano-peras#120`) confirm this is known incomplete production code, not a test-only path. Exploitation requires only the ability to connect to a node and send a well-formed CBOR-encoded `PerasCert` message.

---

### Recommendation

Replace the stub `validatePerasCert` with a complete implementation that:

1. **Verifies the aggregate vote signature** against the public keys of the claimed voters, using the same BLS/aggregate-signing scheme used in `implVerifyCert` for `WFALS`/`EveryoneVotes`.
2. **Cross-references each claimed voter against the canonical committee** derived from the ledger stake distribution for the relevant epoch, rejecting any voter not present in the committee.
3. **Checks that the total stake of verified voters meets the quorum threshold** (`stakeAboveThreshold`) before accepting the certificate.
4. **Validates the certificate round and boosted block** against the current chain state (e.g., the boosted block must exist and be within the valid round window).

The `implVerifyCert` functions in `WFALS.hs` and `EveryoneVotes.hs` provide the correct pattern: they look up each voter in the `extWFAStakeDistr` derived from the ledger, verify signatures, and compute eligibility witnesses before accepting a certificate. [6](#0-5) 

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node over the node-to-node protocol.
2. Construct a `PerasCert` CBOR payload naming a block on an adversarial fork (any valid `Point blk` with a known hash) and an arbitrary round number.
3. Send the message via the Peras certificate diffusion mini-protocol (no stake, no keys, no eligibility proof required).
4. Observe via the node's trace that `ChainSelectionForBoostedBlock` fires for the named block.
5. Confirm via `getCurrentChain` that the node's selection has switched to the fork carrying the fake-boosted block, despite the fork being up to 14 blocks shorter than the honest chain.

The `validatePerasCert` stub at lines 353–358 of `SupportsPeras.hs` is the sole gate that must be bypassed, and it performs no checks. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L402-407)
```haskell
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-540)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
              case nonZero numSeats of
                Nothing ->
                  Left (ZeroNonPersistentSeats seatIndex)
                Just nonZeroNumSeats ->
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
```
