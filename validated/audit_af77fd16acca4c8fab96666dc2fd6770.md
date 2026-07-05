### Title
`validatePerasCert` Stub Unconditionally Accepts All Peras Certificates Without Cryptographic or Semantic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic checks. An unprivileged peer can therefore inject an arbitrarily crafted Peras certificate — with any round number, any boosted-block hash, and no valid aggregate BLS signature — and the node will accept it, store it in `PerasCertDB`, and use it to artificially inflate the chain-selection weight of an adversary-chosen block. This is a direct bypass of the Peras certificate-verification gate that is supposed to guard chain-selection boosting.

---

### Finding Description

**Root cause — the degenerate `BlockSupportsPeras` instance**

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for accepting a Peras certificate:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the entire repository is the catch-all degenerate instance:

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

No cryptographic check (aggregate BLS signature), no round-number check, no boosted-block ancestry check, and no voter-eligibility check is performed. Every certificate is stamped `ValidatedPerasCert` with the full `perasWeight` boost.

**Exploit path**

1. An unprivileged peer connects to a node via the Peras certificate diffusion mini-protocol.
2. The peer sends a crafted `PerasCert` (or `V1.PerasCert`) with an arbitrary `pcCertRound`, an arbitrary `pcBoostedBlock` pointing to a block on the adversary's fork, and a garbage aggregate signature.
3. The inbound handler calls `validatePerasCert`, which returns `Right ValidatedPerasCert{..}` unconditionally.
4. The validated certificate is forwarded to `ChainDB.addPerasCert`, which enqueues a `ChainSelAddPerasCert` event.
5. `chainSelSync` processes the event: it stores the certificate in `PerasCertDB` and calls `chainSelectionForBlock` for the boosted block. [2](#0-1) 

6. `preferAnchoredCandidate` is called with the now-populated `PerasWeightSnapshot`. When Peras weights are non-empty, the function switches from tip-only comparison to a full suffix-weight comparison:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights = ...   -- normal Praos path
  | otherwise =
      case AF.intersect ours cand of
        ...
        Just (..., oursSuffix, candSuffix) ->
          case preferCandidate ...
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of ...
``` [3](#0-2) 

7. The adversary's fork, boosted by the injected certificate, now outweighs the honest chain in `weightedSelectView`, causing the node to switch to the adversarial fork.

**Secondary bypass in `checkPreferTheirsOverOurs`**

The ChainSync client's forecast-horizon disconnect guard hardcodes `emptyPerasWeightSnapshot`, ignoring actual Peras weights when deciding whether to disconnect from a peer whose candidate is beyond the forecast horizon:

```haskell
checkPreferTheirsOverOurs kis
  | shouldSwitch $
      preferAnchoredCandidate
        (configBlock cfg)
        -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
        emptyPerasWeightSnapshot   -- ← always ignores Peras boosts
        ourFrag
        theirFrag = pure ()
  | otherwise = throwSTM CandidateTooSparse ...
``` [4](#0-3) 

This means a peer serving a sparse adversarial chain that would only be preferred *because* of injected Peras boosts will not be disconnected during the forecast-horizon wait, compounding the primary bypass.

---

### Impact Explanation

**Impact: High — Chain selection bug enabling an unprivileged peer to make an honest node prefer a non-canonical chain.**

By injecting a certificate that boosts an adversarial block, an attacker can shift the node's chain-selection decision away from the honest chain. Because `validatePerasCert` never rejects any certificate, the attacker can repeat this for any block on any fork, effectively controlling which chain the node considers "heaviest" under the Peras weight metric. This violates the core Peras security invariant that only legitimately quorum-certified blocks receive a boost.

---

### Likelihood Explanation

**Likelihood: Medium.**

- The attacker requires only an unprivileged peer connection — no keys, no stake, no admin access.
- Peras certificate diffusion is wired into the node's mini-protocol stack and is reachable from any connected peer.
- The stub is the *only* `BlockSupportsPeras` instance in the repository; there is no overriding Cardano-specific instance that would restore validation.
- The attack is deterministic and requires no brute force.

The likelihood is Medium rather than High because Peras is still under active development and may not yet be enabled on mainnet, but the code is present in production modules (not test/mock files) and the diffusion path is live.

---

### Recommendation

1. **Implement `validatePerasCert` properly** before enabling Peras certificate diffusion. At minimum it must verify the aggregate BLS signature over `(pcRoundNo, pcBoostedBlock)` against the committee's aggregate verification key, check that the round number is current, and verify voter eligibility proofs. The `EveryoneVotes.implVerifyCert` and `WFALS.implVerifyCert` implementations in `Ouroboros.Consensus.Committee.EveryoneVotes` and `Ouroboros.Consensus.Committee.WFALS` show the correct pattern. [5](#0-4) 

2. **Remove the degenerate catch-all instance** or gate it behind a compile-time flag that is disabled in production builds, so that any block type without a real `validatePerasCert` implementation fails to compile rather than silently accepting all certificates.

3. **Fix `checkPreferTheirsOverOurs`** to use the real `PerasWeightSnapshot` rather than `emptyPerasWeightSnapshot`, so the forecast-horizon disconnect guard is consistent with the actual chain-selection logic.

---

### Proof of Concept

```
Attacker (peer) → node:
  Send PerasCert {
    pcCertRound    = <current round>,
    pcBoostedBlock = <hash of adversarial fork tip>,
    pcVoters       = <any bitmap>,
    pcSignature    = <garbage bytes>
  }

Node execution path:
  validatePerasCert params cert
    → Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
    -- no signature check, no round check, no voter check

  PerasCertDB.addCert cdbPerasCertDB cert   -- stored
  chainSelectionForBlock ... boostedHdr ...  -- triggered

  preferAnchoredCandidate cfg weights ours cand
    -- weights is now non-empty (adversarial boost applied)
    → ShouldSwitch (Left ...)               -- node switches to adversarial fork
```

The node switches to the adversarial fork without the attacker possessing any stake, keys, or privileged access.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1834-1851)
```haskell
  checkPreferTheirsOverOurs :: KnownIntersectionState blk -> STM m ()
  checkPreferTheirsOverOurs kis
    | -- Precondition is fulfilled as ourFrag and theirFrag intersect by
      -- construction.
      shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
          emptyPerasWeightSnapshot
          ourFrag
          theirFrag =
        pure ()
    | otherwise =
        throwSTM $
          CandidateTooSparse
            mostRecentIntersection
            (ourTipFromChain ourFrag)
            (theirTipFromChain theirFrag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L292-340)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
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

    -- Return the list of voters attesting the election winner
    pure members
```
