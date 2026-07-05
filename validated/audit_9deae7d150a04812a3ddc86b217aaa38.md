### Title
Peras Vote and Certificate Validation Stubs Perform No Cryptographic Verification, Enabling Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` (always accepts) and `validatePerasVote` as a pure stake-distribution lookup with no signature check. Any unprivileged peer can inject crafted Peras certificates or votes over the vote/cert diffusion mini-protocols and have them accepted as valid, bypassing the quorum requirement entirely.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two critical validation entry points: `validatePerasCert` and `validatePerasVote`. The only production instance of this class (the catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements both as stubs:

**`validatePerasCert`** — always returns `Right`, accepting every certificate unconditionally:

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

**`validatePerasVote`** — only checks whether the voter ID appears in the stake distribution map; no signature, no VRF proof, no committee eligibility check:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

These stubs are called directly from the network-facing inbound processing functions. `processCerts` in the cert diffusion pool calls `validateCert` on every inbound certificate batch and adds all that pass to the `PerasCertDB`: [3](#0-2) 

`processVotes` in the vote diffusion pool calls `validatePerasVote mkPerasParams sd vote` on every inbound vote: [4](#0-3) 

The `PerasVoteId` deduplication in `implAddVote` only prevents the same `(roundNo, voterId)` pair from being counted twice — it does not prevent an attacker from impersonating multiple distinct pool IDs: [5](#0-4) 

The `PerasVoteId` type encodes only `(PerasRoundNo, PerasVoterId)` — no block target — so the deduplication guard does not prevent a voter from casting votes for different blocks in the same round via separate connections: [6](#0-5) 

The model itself acknowledges this gap explicitly:

> "NOTE: this is under the assumption that a voter doesn't cast two different votes for the same round (that is, with the same ID but different body)." [7](#0-6) 

---

### Impact Explanation

**For `validatePerasCert`:** Because the stub unconditionally returns `Right`, any peer can send a crafted `PerasCert` for any `(PerasRoundNo, Point blk)` pair. The certificate is timestamped and inserted into the `PerasCertDB` without any quorum proof. The Peras chain-selection logic then uses this certificate to apply a boost weight (`perasWeight`) to the attacker-chosen block, making it preferred over honest competing chains. This is a direct bypass of the Peras quorum requirement — the attacker does not need to control any stake.

**For `validatePerasVote`:** Once the stake distribution is properly plumbed (the current `mempty` placeholder is replaced), an attacker can craft `PerasVote` messages claiming any pool ID present in the distribution. Each such vote is accepted with that pool's full stake weight. By impersonating enough pools, the attacker can accumulate stake above the quorum threshold and trigger certificate forging for an attacker-chosen block — analogous to the reported "double voting" pattern where stake is counted multiple times without the legitimate owner's participation.

Both paths lead to the same outcome: a forged Peras certificate boosts an attacker-controlled block in chain selection, constituting a consensus safety failure.

---

### Likelihood Explanation

The cert bypass (`validatePerasCert` always `Right`) is immediately reachable by any peer connected via the Peras cert diffusion mini-protocol. No stake, no keys, and no special privileges are required — only a network connection and knowledge of a valid `(PerasRoundNo, Point blk)` pair (both observable from the chain). The vote bypass becomes equally reachable once the stake distribution is wired in (a tracked TODO). The diffusion handlers are registered unconditionally for all node-to-node connections: [8](#0-7) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate verification against the `VotingCommittee` for the relevant epoch. This must include: verifying the aggregate BLS signature over the claimed voter set, checking each voter's eligibility (persistent membership or VRF-based non-persistent sortition), and confirming the total stake of the voter set exceeds the quorum threshold. The `implVerifyCert` functions in `WFALS.hs` and `EveryoneVotes.hs` provide the correct committee-level logic and should be wired into the `BlockSupportsPeras` instance. [9](#0-8) 

2. **`validatePerasVote`**: Implement cryptographic signature verification (BLS vote signature) and, for non-persistent voters, VRF eligibility proof verification. The `implVerifyVote` functions in `WFALS.hs` and `EveryoneVotes.hs` already implement this logic at the committee layer and must be connected to the `BlockSupportsPeras` validation path. [10](#0-9) 

3. **Equivocation handling**: The `PerasVoteId` deduplication guards against the same `(roundNo, voterId)` being counted twice, but the model explicitly assumes a voter does not cast two different votes for the same round. Equivocating votes (same ID, different block target) arriving via separate connections should be detected and the peer disconnected, not silently ignored.

---

### Proof of Concept

```
1. Attacker observes the current chain tip: block B at slot S, round R.
2. Attacker connects to an honest node via the Peras cert diffusion mini-protocol.
3. Attacker sends a crafted PerasCert { pcCertRound = R, pcCertBoostedBlock = B' }
   where B' is any block the attacker wishes to boost (e.g., their own fork tip).
4. processCerts calls validatePerasCert, which returns Right unconditionally.
5. The certificate is inserted into the PerasCertDB with the node's current wall-clock time.
6. The Peras chain-selection logic applies perasWeight boost to B', making it
   preferred over honest competing chains that lack a certificate.
7. The honest node switches to the attacker's fork.
```

No stake, no cryptographic keys, and no quorum of real voters is required. The only prerequisite is a network connection to the target node.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L188-193)
```haskell
data PerasVoteId blk = PerasVoteId
  { pviRoundNo :: !PerasRoundNo
  , pviVoterId :: !PerasVoterId
  }
  deriving stock (Show, Eq, Ord, Generic)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L138-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L150-152)
```haskell
  --
  -- NOTE: this is under the assumption that a voter doesn't cast two different
  -- votes for the same round (that is, with the same ID but different body).
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-409)
```haskell
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-494)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```
