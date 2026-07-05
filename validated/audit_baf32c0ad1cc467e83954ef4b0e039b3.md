### Title
Peras Certificate and Vote Signature Validation Unconditionally Bypassed in Default `BlockSupportsPeras` Instance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance — which is the only instance in the codebase and therefore applies to all block types including Cardano blocks — implements `validatePerasCert` as an unconditional `Right` (accept-all) and `validatePerasVote` without any BLS signature check. An unprivileged peer can send a crafted `PerasCert` or `PerasVote` over the Peras miniprotocol, and the node will accept it as fully validated, allowing the attacker to inject arbitrary certificates that influence chain selection via the Peras boosting mechanism.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two critical validation methods:

```haskell
validatePerasCert :: PerasCfg blk -> PerasCert blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote :: PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The sole instance in the codebase — `instance StandardHash blk => BlockSupportsPeras blk` — implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

This unconditionally wraps any incoming `PerasCert` in `ValidatedPerasCert` without verifying the aggregate BLS signature, the voter set, the round number bounds, or any other structural property. [1](#0-0) 

Similarly, `validatePerasVote` only checks stake distribution membership but performs no BLS vote signature verification:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [2](#0-1) 

The production inbound-certificate path in `processCerts` calls `validatePerasCert mkPerasParams` directly: [3](#0-2) 

And `processVotes` calls `validatePerasVote mkPerasParams sd vote` for every inbound vote: [4](#0-3) 

The `processCerts` function itself reads the "already in DB" set atomically, then calls `validateCert` (the no-op), then calls `addCert` outside the STM boundary — meaning the only gate between a peer-supplied `PerasCert` and a committed `ValidatedPerasCert` in the `PerasCertDB` is a round-number deduplication check, not any cryptographic check: [5](#0-4) 

The `implAddCert` function in `PerasCertDB` then stores the certificate and updates `pcdsLatestCertSeen`, which feeds directly into the Peras chain-selection boosting weight: [6](#0-5) 

The `PerasVoteDB` implementation carries the same explicit TODO: [7](#0-6) 

The real BLS aggregate-signature verification logic exists in `WFALS.hs` and `EveryoneVotes.hs` under the `VotingCommittee` class, but those methods (`verifyCert`, `verifyVote`) are **not called** in the inbound certificate/vote processing pipeline — only `validatePerasCert`/`validatePerasVote` from `BlockSupportsPeras` are called, and those are the no-op stubs. [8](#0-7) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote signature validation enabling unauthorized certificate acceptance.**

An attacker can craft a `PerasCert` for any block point and any round number, send it to a node via the Peras certificate miniprotocol, and the node will accept it as a `ValidatedPerasCert` with full boosting weight. Because `pcdsLatestCertSeen` is updated with the attacker's certificate, the node's chain-selection logic will apply Peras boost to the attacker-chosen block, potentially causing the node to prefer a non-canonical or adversarially-chosen chain over the honest chain. This directly undermines the Peras protocol's safety guarantee that only quorum-certified blocks receive a boost.

---

### Likelihood Explanation

Any unprivileged peer connected via the Peras certificate miniprotocol can trigger this. No key material, stake, or privileged access is required — only the ability to send a well-formed CBOR-encoded `PerasCert` message. The `PerasCert` type is serialisable and its structure is public. [9](#0-8) 

---

### Recommendation

1. Implement `validatePerasCert` to call the appropriate `VotingCommittee.verifyCert` method (e.g., `WFALS.implVerifyCert` or `EveryoneVotes.implVerifyCert`) and reject certificates with invalid aggregate BLS signatures, out-of-bounds voter sets, or mismatched round numbers.
2. Implement `validatePerasVote` to call `VotingCommittee.verifyVote` (e.g., `WFALS.checkVoteSignature`) to verify the per-vote BLS signature before accepting the vote.
3. Until these are implemented, consider gating the Peras certificate/vote miniprotocol behind a feature flag so that nodes not yet running the full validation logic do not accept inbound Peras objects from peers.

---

### Proof of Concept

Attacker-controlled entry path:

```
peer sends PerasCert { pcCertRound = R, pcCertBoostedBlock = attacker_block }
  → makePerasCertPoolWriterFromChainDB.opwAddObjects
  → processCerts systemTime (ChainDB.getPerasCertIds chainDB) (validatePerasCert mkPerasParams) ...
  → validatePerasCert mkPerasParams cert
      = Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
        -- no signature check, unconditional accept
  → addCert (WithArrivalTime now validatedCert)
  → implAddCert: pcdsLatestCertSeen updated to attacker's cert
  → chain selection applies Peras boost to attacker_block
```

The `validatePerasCert` stub is the necessary vulnerable step: it is the sole gate between a peer-supplied `PerasCert` and a committed `ValidatedPerasCert`, and it performs no cryptographic verification. [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L541-586)
```haskell
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
