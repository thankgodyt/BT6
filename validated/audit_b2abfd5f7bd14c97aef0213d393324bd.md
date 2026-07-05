### Title
Missing Peras Certificate Cryptographic Validation Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) without performing any cryptographic or structural validation. This is the instance used for all block types in the production inbound certificate processing pipeline. An unprivileged peer can inject a crafted `PerasCert` message pointing to any block, which will be accepted, stored in the `PerasCertDB`, and trigger chain selection with an artificial Peras weight boost — potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

The degenerate `BlockSupportsPeras` instance (applied universally to all `StandardHash blk` types) implements `validatePerasCert` as an unconditional success:

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

The `PerasCert blk` data type in this instance carries only `pcCertRound` and `pcCertBoostedBlock` — no cryptographic proof, no aggregate BLS signature, no committee membership witness. There is nothing to verify, and the function never rejects any input. [2](#0-1) 

**Production inbound path — peer-received certificates flow through this stub:**

`makePerasCertPoolWriterFromChainDB` is the production writer used by the ObjectDiffusion mini-protocol to handle certificates received from peers. It passes `validatePerasCert mkPerasParams` directly to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`processCerts` calls the validator on each inbound cert and, if all pass (which they always do), adds them to the database: [4](#0-3) 

**Chain selection impact — accepted cert triggers fork switch:**

Once stored, the cert is processed by `chainSelSync`, which adds the cert's boosted block to the `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block: [5](#0-4) 

Chain selection then uses `preferAnchoredCandidate`, which computes `weightedSelectView` — adding the Peras weight boost from the `PerasWeightSnapshot` to the candidate fragment's total weight: [6](#0-5) 

The `WeightedSelectView` comparison prefers the candidate if its `wsvTotalWeight` (block number + weight boost) exceeds the current chain's: [7](#0-6) 

**Contrast with the real committee-based validation that exists but is bypassed:**

The `EveryoneVotes` and `WFALS` committee implementations in `implVerifyCert` perform full BLS aggregate signature verification, committee membership checks, and VRF output verification. These are never reached because the universal degenerate instance intercepts all calls first. [8](#0-7) 

---

### Impact Explanation

**Severity: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

When Peras is enabled with a non-zero `perasWeight`, an attacker who can send a single crafted `PerasCert` message (reachable via the ObjectDiffusion mini-protocol, no keys required) can:

1. Inject a certificate claiming to boost any block on a minority fork.
2. The certificate passes validation unconditionally.
3. The boosted block's chain gains artificial weight equal to `perasWeight params`.
4. If this artificial weight causes the minority fork's total weight to exceed the honest chain's total weight, the node switches to the minority fork.
5. This constitutes a chain selection manipulation: an honest node is made to prefer a non-canonical chain without any legitimate quorum of committee votes.

The `PerasCert` data type in the degenerate instance carries no cryptographic content, so there is no signature to forge — the attacker simply constructs a `PerasCert{pcCertRound, pcCertBoostedBlock}` with arbitrary values.

---

### Likelihood Explanation

**Conditional on Peras being enabled.** The CHANGELOG notes that "if Peras is disabled (which is the default), there is no observable difference." However:

- The validation bypass is present in production code today.
- The ObjectDiffusion mini-protocol and `processCerts` pipeline are active regardless of whether Peras weight is non-zero.
- When Peras is enabled (the intended production state), the bypass is immediately exploitable by any peer with a network connection — no keys, no stake, no privilege required.
- The attack requires sending a single well-formed CBOR-encoded `PerasCert` message, which is trivially constructable from the public type definition.

---

### Recommendation

1. **Do not use the degenerate `BlockSupportsPeras` instance in the production inbound certificate path.** The `validatePerasCert` stub must not be called on peer-supplied data until it performs real validation.
2. **Implement cryptographic validation** in `validatePerasCert` before enabling Peras: verify the aggregate BLS signature over the election ID and candidate block, verify committee membership and quorum, and verify proofs of possession for all voter keys — as already implemented in `implVerifyCert` for `EveryoneVotes` and `WFALS`.
3. **Gate the inbound pipeline** so that `processCerts` / `makePerasCertPoolWriterFromChainDB` only accepts certificates when a real (non-stub) `validatePerasCert` implementation is in place.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Connect to a target node as a peer via the ObjectDiffusion mini-protocol (no authentication required).
2. Construct a `PerasCert` value:
   ```
   PerasCert
     { pcCertRound    = <any round number not yet in DB>
     , pcCertBoostedBlock = <point of a block on a minority fork>
     }
   ```
3. Send it via the `opwAddObjects` handler of `makePerasCertPoolWriterFromChainDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..}` unconditionally.
5. The cert is stored via `ChainDB.addPerasCertAsync`.
6. `chainSelSync` fires, adds the cert's boost to the `PerasWeightSnapshot`, and calls `chainSelectionForBlock` for the boosted block.
7. `preferAnchoredCandidate` now computes the minority fork's total weight as `blockNo + perasWeight`, which may exceed the honest chain's block number alone.
8. The node switches to the minority fork. [9](#0-8) [3](#0-2) [5](#0-4)

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
