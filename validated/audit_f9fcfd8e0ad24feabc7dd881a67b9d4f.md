### Title
Peras Vote Impersonation via Missing Cryptographic Signature Verification Allows Unauthorized Certificate Forging and Chain Selection Manipulation - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production default instance of `validatePerasVote` in `BlockSupportsPeras` accepts any inbound `PerasVote` as valid if the claimed `pvVoteVoterId` appears in the stake distribution, without verifying any cryptographic proof that the sender controls that voter's key. The `PerasVote blk` data type itself carries no signature field. An unprivileged peer can therefore craft votes impersonating any registered stake pool, accumulate a quorum of fake votes, trigger automatic certificate forging, and cause honest nodes to apply a Peras weight boost to an attacker-chosen block — directly manipulating chain selection.

### Finding Description

**Root cause — no signature in the wire vote type:**

The default `PerasVote blk` data type (the only instance wired into the diffusion layer) carries three fields: a round number, a target block, and a voter ID:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- KeyHash StakePool, no signature
  }
``` [1](#0-0) 

There is no `pvSignature` field. Any peer can construct a `PerasVote` claiming to be any `PerasVoterId`.

**Root cause — `validatePerasVote` performs only a stake-distribution lookup:**

The production default instance of `validatePerasVote` (the `instance StandardHash blk => BlockSupportsPeras blk` catch-all used for all block types in the diffusion layer) does nothing beyond checking whether the claimed voter ID is present in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` is a plain `Map.lookup` on `pvVoteVoterId`: [3](#0-2) 

No signature is checked, no VRF proof is verified, no committee membership proof is required.

**Attack entry path — peer-facing vote diffusion:**

Both production `ObjectPoolWriter` instances (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) call `processVotes`, which calls `validatePerasVote` on every inbound vote received from a peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) [5](#0-4) 

`processVotes` timestamps and stores every vote that passes this check: [6](#0-5) 

**Quorum triggers automatic certificate forging:**

`implAddVote` in `PerasVoteDB.Impl` calls `updatePerasRoundVoteStates` on every stored vote. When accumulated stake crosses the quorum threshold, a `ValidatedPerasCert` is automatically forged and returned: [7](#0-6) 

`addPerasVoteWithAsyncCertHandling` then enqueues this certificate into the ChainDB's chain-selection queue: [8](#0-7) 

The certificate applies a Peras weight boost (`vpcCertBoost = perasWeight params`) to the attacker-chosen block, directly influencing which chain the node considers heaviest.

**`validatePerasCert` is also a no-op stub:**

The same degenerate instance unconditionally accepts every inbound certificate:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [9](#0-8) 

This means a peer can also directly inject a pre-formed certificate without going through the vote accumulation path.

**Contrast with the properly implemented committee schemes:**

The `WFALS` and `EveryoneVotes` committee implementations in `Ouroboros.Consensus.Committee` do perform full cryptographic verification (BLS signature + VRF proof) on every vote and certificate. The vulnerability is that the `BlockSupportsPeras` default instance — the one actually wired into the peer-facing diffusion layer — bypasses all of this. [10](#0-9) 

### Impact Explanation

**Severity: Critical / High.**

An unprivileged peer with no keys can:

1. Read the current stake distribution (public information).
2. Craft `PerasVote` messages claiming to be any set of registered stake pools whose combined stake exceeds the quorum threshold.
3. Send these votes via the object-diffusion miniprotocol.
4. Cause the receiving node to automatically forge a `ValidatedPerasCert` boosting an attacker-chosen block.
5. This certificate is enqueued into chain selection, causing the node to prefer the boosted chain over the canonical chain.

This is a **Peras voting/certificate verification bypass** that enables unauthorized certificate acceptance and chain selection manipulation — matching the "Critical: bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance" and "High: chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

### Likelihood Explanation

**High.** The attack requires only:
- Network connectivity to a target node (standard peer connection).
- Knowledge of the current stake distribution (publicly available on-chain).
- Ability to send well-formed CBOR-encoded `PerasVote` messages.

No keys, no stake, no privileged access are required. The degenerate `BlockSupportsPeras` instance is the only instance in scope for the diffusion layer, confirmed by the `getPerasCertInBlock _ = Nothing` stub showing no era-specific override exists.

### Recommendation

1. **Add a `pvSignature` field to `PerasVote blk`** (or use the already-defined `Ouroboros.Consensus.Peras.Vote.V1.PerasVote` which includes `pvSignature :: VoteSignature PerasBLSCrypto`). [11](#0-10) 

2. **Implement `validatePerasVote` to verify the BLS signature** against the voter's public key derived from the stake distribution, analogous to `implVerifyVote` in `WFALS.hs`.

3. **Implement `validatePerasCert` to verify the aggregate signature** over the declared voter set, analogous to `implVerifyCert` in `WFALS.hs`.

4. **Do not deploy the Peras vote/cert diffusion miniprotocol** until the validation stubs (tracked in `https://github.com/tweag/cardano-peras/issues/120`) are replaced with real cryptographic checks.

### Proof of Concept

**Attacker preconditions:** peer connection to target node; knowledge of stake distribution (public).

**Exploit sequence:**

```
1. Read PerasVoteStakeDistr from the node's public ledger state.
2. Select any set of PerasVoterIds whose combined PerasVoteStake
   exceeds perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin.
3. For each selected voterId, craft:
     PerasVote { pvVoteRound    = <current round>
               , pvVoteBlock    = <attacker-chosen block point>
               , pvVoteVoterId  = voterId }
   No signature is needed.
4. Send the batch via the object-diffusion miniprotocol.
5. processVotes calls validatePerasVote for each vote.
   validatePerasVote succeeds (Map.lookup finds the voterId).
6. Each ValidatedPerasVote is stored in PerasVoteDB.
7. updatePerasRoundVoteStates detects quorum; implAddVote returns
   AddedPerasVoteAndGeneratedNewCert cert.
8. addPerasVoteWithAsyncCertHandling enqueues cert into ChainDB.
9. Chain selection applies vpcCertBoost to the attacker-chosen block,
   causing the node to prefer the attacker's fork.
```

The `PerasVote blk` data type carries no signature field, so step 3 requires zero cryptographic material. [1](#0-0) [2](#0-1) [4](#0-3) [12](#0-11) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L104-113)
```haskell
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-211)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L315-328)
```haskell
addPerasVoteWithAsyncCertHandling ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
addPerasVoteWithAsyncCertHandling cdb@CDB{cdbPerasVoteDB} vote = do
  addVoteRes <- join . atomically . addVote cdbPerasVoteDB $ vote
  case addVoteRes of
    AddedPerasVoteAndGeneratedNewCert cert -> do
      let certTime = getArrivalTime vote
      promise <- addPerasCertAsync cdb (WithArrivalTime (certTime) cert)
      pure (addVoteRes, Just promise)
    _ -> pure (addVoteRes, Nothing)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-350)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```
