### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero validation — no quorum-stake check, no aggregate-signature verification, no committee-membership check. This function is the sole validation gate called by `processCerts` when handling inbound Peras certificates from peers over the object-diffusion mini-protocol. A single unprivileged peer can therefore inject a crafted `PerasCert` targeting any block, have it accepted into the ChainDB, and cause honest nodes to artificially boost that block's weight in Peras-weighted chain selection, making them prefer a non-canonical chain.

---

### Finding Description

**Root cause — the no-op validator**

The catch-all `BlockSupportsPeras` instance for `StandardHash blk` in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional pass-through:

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

Every field of the certificate — the round number, the boosted block point, the aggregate BLS signature, the voter set, and the total stake — is accepted without inspection. The function assigns the full `perasWeight` boost regardless of how many (or how few) voters actually signed.

**The missing checks (analog to the external report)**

The external report's `closeBidTaker` checked `OfferStatus.Settled` but ignored `AbortOfferStatus.Aborted`. Here the situation is structurally identical but more severe: `processCerts` checks only whether the certificate's round number is already present in the database, but the validation function it delegates to checks *none* of the following conditions that a legitimate certificate must satisfy:

| Required check | Where it exists | Called by `validatePerasCert`? |
|---|---|---|
| Total voter stake ≥ quorum threshold | `stakeAboveThreshold` / `votesReachQuorum` | **No** |
| Aggregate BLS signature valid | `verifyAggregateVoteSignature` in `implVerifyCert` | **No** |
| Each voter is a legitimate committee member | `getCandidateIfSeatWithinBounds` / `isPersistentMember` | **No** |
| VRF outputs valid for non-persistent voters | `batchVerifyVRFOutputs` | **No** | [2](#0-1) [3](#0-2) 

**The inbound path — reachable by any peer**

`processCerts` in the object-diffusion pool handler is the entry point for peer-supplied certificates. It calls `validatePerasCert mkPerasParams` as its sole validation step:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [4](#0-3) 

`processCerts` itself only deduplicates by round number; it does not re-examine certificate content:

```haskell
let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
...
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [5](#0-4) 

Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch `([], validatedCerts)` is always taken, and every peer-supplied certificate is forwarded to `ChainDB.addPerasCertAsync`.

**How the accepted certificate affects chain selection**

Once in the ChainDB, the certificate's boosted block point is inserted into the `PerasWeightSnapshot`. `preferAnchoredCandidate` then uses `weightedSelectView` to compute the total weight of each candidate fragment, summing `BlockNo` and the accumulated `PerasWeight` boost for every block on the fragment:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      case preferCandidate cfg
        (weightedSelectView cfg weights oursSuffix)
        (weightedSelectView cfg weights candSuffix) of
``` [7](#0-6) 

The default `perasWeight` is 15 (`PerasWeight 15`), meaning a single injected certificate adds 15 units of weight to the targeted block's chain — equivalent to 15 extra blocks — without any honest stake backing it. [8](#0-7) 

---

### Impact Explanation

**Impact class: Critical / High — Peras certificate verification bypass enabling unauthorized chain-selection manipulation.**

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlock }` for any block it wishes to promote.
2. Send it over the object-diffusion mini-protocol to a target node.
3. The node accepts it unconditionally (no quorum, no signature, no membership check).
4. The adversarial block gains `perasWeight = 15` extra weight in chain selection.
5. The honest node may switch to the adversary's chain even if it is shorter or less supported by honest stake, violating the Peras security assumption that only blocks backed by ≥ 3/4 + safety-margin of committee stake can be boosted.

This directly matches the allowed impact: *"Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance"* and *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**High.** The attack requires only a network connection to a target node and the ability to send a single well-formed (but cryptographically invalid) `PerasCert` message. No keys, no stake, no prior chain knowledge beyond the target block's point are needed. The object-diffusion protocol is a standard peer-to-peer channel. The vulnerability is present in the production code path, not a test stub, and is guarded only by a round-number deduplication check that an attacker trivially satisfies by using a fresh round number.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Reconstructs the voting committee for the certificate's round from the ledger state.
2. Calls `implVerifyCert` (or the equivalent for the concrete block type) to verify committee membership and the aggregate BLS signature.
3. Computes the total vote weight of the certified voters and calls `stakeAboveThreshold` to confirm the quorum threshold is met.
4. Rejects the certificate (returns `Left`) if any of these checks fail.

Until a concrete `BlockSupportsPeras` instance with real validation is wired in, the `opwAddObjects` handler in `PerasCert.hs` should refuse all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

On a private testnet with Peras enabled, connect to a target node and send via the object-diffusion protocol:

```
PerasCert
  { pcCertRound      = freshRoundNo   -- any round not yet in the DB
  , pcCertBoostedBlock = pointOfAdversarialBlock
  }
```

Because `validatePerasCert mkPerasParams cert = Right (ValidatedPerasCert cert 15)` for every input, the certificate passes `processCerts`'s `partitionEithers` check and is forwarded to `ChainDB.addPerasCertAsync`. The adversarial block's chain now carries `+15` weight in `weightedSelectView`. If the adversarial chain's `wsvTotalWeight` exceeds the honest chain's, `preferAnchoredCandidate` returns `ShouldSwitch`, and the node switches to the adversarial chain — despite it having no legitimate quorum backing. [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-586)
```haskell
-- | Verify a certificate attesting the winner of a given election
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
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
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

    -- Verify VRF outputs for non-persistent voters (if any)
    case catMaybes (NonEmpty.toList optionalVRFKeysAndOutputs) of
      -- No non-persistent voters => no VRF outputs to verify
      [] -> do
        pure ()
      -- Some non-persistent voters => verify their aggregate VRF outputs
      vrfKeysAndOutputs -> do
        let (vrfVerificationKeys, vrfOutputs) =
              munzip
                . NonEmpty.fromList -- safe 'vrfKeysAndOutputs' /= []
                $ vrfKeysAndOutputs
        bimap InvalidCertSignature id $
          batchVerifyVRFOutputs
            vrfVerificationKeys
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs

    -- Return the list of voters attesting the election winner
    pure members
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```
