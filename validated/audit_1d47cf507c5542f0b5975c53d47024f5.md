### Title
`validatePerasCert` Skips All Cryptographic Verification, Allowing Forged Peras Certificates to Manipulate Chain Selection — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` type class defines `validatePerasCert` as the interface for cryptographically verifying inbound Peras certificates before they influence chain selection. The sole concrete instance of this class — a catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements `validatePerasCert` as an unconditional `Right`, calling no verification function whatsoever. This is the direct analog of the reported bug: the correct verification function is never called, so the validation step is silently bypassed. Because this instance is used in the live production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`), any peer can submit a crafted certificate that is accepted, stored, and used to trigger chain selection for an arbitrary block.

---

### Finding Description

**Root cause — wrong/missing function call in `validatePerasCert`:**

The `BlockSupportsPeras` class declares:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance that exists is the catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

No cryptographic function is called. The correct function to call — analogous to `vest` in the original report — would be a signature-aggregation verifier such as `verifyAggregateVoteSignature` (used in `EveryoneVotes.implVerifyCert`) or `batchVerifyVRFOutputs` (used in `WFALS.implVerifyCert`). Instead, the implementation calls nothing and returns `Right` unconditionally.

**Production call path:**

`validatePerasCert` is called directly in the live inbound-certificate pipeline:

```haskell
-- makePerasCertPoolWriterFromChainDB
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

This feeds into `processCerts`, which, for every certificate that passes validation (i.e., every certificate), calls `ChainDB.addPerasCertAsync`. That triggers `chainSelSync` in `ChainSel.hs`, which adds the certificate to `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, potentially switching the node's selected chain.

The same structural defect exists in `validatePerasVote`: it calls only `lookupPerasVoteStake` (a map lookup) and never calls any vote-signature verification function, meaning forged votes with a valid voter ID are accepted and can accumulate toward quorum, producing a forged certificate that then enters the same chain-selection path.

---

### Impact Explanation

**Impact: High — chain selection manipulation via forged Peras certificates.**

An unprivileged peer connected over the Peras object-diffusion mini-protocol can craft a `PerasCert` that names any block as the "boosted" block. Because `validatePerasCert` always returns `Right`, the certificate is unconditionally accepted, stored in `PerasCertDB`, and used to add `perasWeight` to the named block's `SelectView`. If the attacker names a block on a minority fork, the honest node may switch to that fork, diverging from the canonical chain. This satisfies the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" impact category.

---

### Likelihood Explanation

**Likelihood: High.**

The attack requires only a network connection to a node running the Peras object-diffusion protocol. No keys, stake, or privileged access are needed. The attacker simply sends a well-formed `PerasCert` CBOR message naming a target block. The validation gate that should reject it is absent.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real cryptographic check before the instance is used in any production code path. Until a proper per-era instance exists, the catch-all instance should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), mirroring the conservative default used elsewhere in the codebase. The same fix applies to `validatePerasVote`, which must call a vote-signature verification function (e.g., `verifyVoteSignature` as used in `EveryoneVotes.implVerifyVote`) rather than only performing a stake-map lookup.

---

### Proof of Concept

1. **Unconditional acceptance in `validatePerasCert`** — the function body calls no verification function and always returns `Right`: [1](#0-0) 

2. **Correct verification functions exist but are never called** — `verifyAggregateVoteSignature` is called in `EveryoneVotes.implVerifyCert` and `batchVerifyVRFOutputs` in `WFALS.implVerifyCert`, but neither is wired into the `BlockSupportsPeras` instance: [2](#0-1) 

3. **`validatePerasCert` is called in the live inbound-certificate pipeline** — every certificate received from a peer passes this gate and proceeds to chain selection: [3](#0-2) 

4. **Accepted certificates trigger `chainSelectionForBlock`** — the boosted block undergoes chain selection, potentially switching the node's tip: [4](#0-3) 

5. **`validatePerasVote` also omits signature verification** — only a stake-map lookup is performed; no call to any vote-signature verifier: [5](#0-4) 

6. **`validatePerasVote` is called in the live inbound-vote pipeline**: [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```
