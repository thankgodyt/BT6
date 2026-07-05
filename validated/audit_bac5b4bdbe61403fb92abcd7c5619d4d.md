### Title
Peras Vote and Certificate Signatures Lack Chain-Specific Binding, Enabling Cross-Fork Replay — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs`)

---

### Summary

The BLS message hashed and signed for every Peras vote in `hashVoteSignature` encodes only `roundNo || boostedBlock.slot || boostedBlock.hash`. It contains no network magic, genesis hash, or any other chain-specific identifier. A valid Peras vote or certificate produced on one Cardano network (or one side of a fork) is therefore cryptographically valid on any other network or fork that shares the same block at the same slot and round number. An unprivileged peer can collect votes from one chain and replay them over the Peras vote-diffusion miniprotocol to nodes on a diverged chain, causing those nodes to accept certificates that were never legitimately produced for their chain and to boost the wrong block during chain selection.

---

### Finding Description

`hashVoteSignature` in `Ouroboros.Consensus.Peras.Crypto.BLS` constructs the message that every Peras committee member signs:

```haskell
hashVoteSignature roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
``` [1](#0-0) 

The signed payload is exactly `roundNo (8 bytes) || slot (8 bytes) || blockHash (32 bytes)`. No network magic, genesis hash, chain ID, or epoch nonce is mixed in. The same function is used for both individual vote signing/verification and for the aggregate BLS certificate signature:

```haskell
verifyAggregateVoteSignature _ aggPk roundNo boostedBlock aggSig =
  BLS.verifyWithRole @SIGN
    (unPerasBLSCryptoAggregateVoteVerificationKey aggPk)
    (hashVoteSignature roundNo boostedBlock)
    (unPerasBLSCryptoAggregateVoteSignature aggSig)
``` [2](#0-1) 

The concrete `PerasVote` wire type carries `pvRoundNo`, `pvBoostedBlock`, and `pvSignature` — nothing chain-specific: [3](#0-2) 

Likewise, `PerasCert` carries only `pcRoundNo`, `pcBoostedBlock`, `pcVoters`, and `pcSignature`: [4](#0-3) 

**Contrast with existing Cardano signing**: Byron block signatures include `ProtocolMagicId` directly in `ContextDSIGN`: [5](#0-4) 

Shelley/Praos/TPraos block headers are KES-signed over a `HeaderBody` that includes the previous block hash (chain-linking) and the epoch nonce (chain-specific entropy). Peras vote signatures have neither.

The VRF eligibility input (`hashVRFInput`) does include the epoch nonce, so non-persistent committee members' eligibility proofs are chain-specific. However, the **vote signature itself** — which is what `verifyVoteSignature` and `verifyAggregateVoteSignature` check — does not include the epoch nonce: [6](#0-5) 

For **persistent committee members** (who carry no VRF proof at all), the vote is entirely replayable across chains. For non-persistent members, the VRF eligibility proof would fail on a different chain, but the aggregate certificate path in `EveryoneVotes.implVerifyCert` and `WFALS.implVerifyCert` verifies the aggregate BLS signature using `verifyAggregateVoteSignature`, which calls `hashVoteSignature` — still without any chain binding: [7](#0-6) 

Inbound votes are accepted via `processVotes` in the Peras vote-diffusion inbound handler, which calls `validatePerasVote` — an unprivileged, unauthenticated peer path: [8](#0-7) 

---

### Impact Explanation

Peras certificates boost the chain-selection weight of the block they certify. A replayed certificate from chain A, accepted by a node on chain B, causes that node to assign extra weight to a block that the legitimate Peras committee of chain B never voted for. This can make an honest node on chain B prefer a non-canonical chain — a **chain-selection bug triggered by an unprivileged peer** submitting crafted (replayed) network messages. In a fork scenario where both chains share a common ancestor block, the replayed votes are indistinguishable from legitimate ones at the cryptographic level.

---

### Likelihood Explanation

The attack requires a fork scenario where both chains share at least one common block (guaranteed for any fork that diverges after genesis). The attacker needs only a standard peer connection to the target node's Peras vote-diffusion miniprotocol — no keys, no stake, no privileged access. The `perasVoteDiffusionProtocol` is exposed to all connected peers: [9](#0-8) 

Mainnet/testnet splits and contentious hard forks are realistic scenarios for a long-lived protocol. The attack is passive (collect-and-replay) and requires no cryptographic capability beyond network access.

---

### Recommendation

Include a chain-specific domain-separation tag in `hashVoteSignature`. The most natural choice is the network magic (already present in `ShelleyConfig` as `shelleyNetworkMagic`) or the genesis hash. A minimal fix:

```haskell
hashVoteSignature networkMagic roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (4 + 8 + 8 + 32)
    $ networkMagicBytes
      <> roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
```

`networkMagic` should be threaded through `CryptoSupportsVoteSigning.signVote` / `verifyVoteSignature` and `CryptoSupportsAggregateVoteSigning.verifyAggregateVoteSignature`. Alternatively, include the genesis hash (as Byron does via `ProtocolMagicId`) for stronger chain binding. The fix must be applied consistently to both individual vote signing and aggregate certificate verification.

---

### Proof of Concept

1. Node A runs on mainnet. Node B runs on a fork that diverged at slot S+1. Both share block `B` at slot `S`.
2. In Peras round `R`, mainnet committee members sign votes for block `B`: `sig_i = BLS.sign(sk_i, hash(R || S || hash(B)))`.
3. Attacker collects these votes from mainnet via the public vote-diffusion protocol.
4. Attacker connects to a node on the fork and submits the same votes via `perasVoteDiffusionProtocol`.
5. The fork node calls `verifyVoteSignature pk R B sig_i` → `BLS.verify(pk, hash(R || S || hash(B)), sig_i)` → **succeeds**, because the signed message is identical on both chains.
6. If enough replayed votes accumulate to reach quorum, `votesReachQuorum` triggers certificate forging, and `addPerasCertAsync` inserts the certificate into the fork node's ChainDB, boosting block `B`'s weight in chain selection — a block the fork's own committee never voted for. [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L88-115)
```haskell
hashVoteSignature ::
  ElectionId PerasBLSCrypto ->
  VoteCandidate PerasBLSCrypto ->
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVoteSignature roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
 where
  roundNoBytes =
    BS.word64BE
      . unPerasRoundNo
      $ roundNo
  boostedBlockSlotBytes =
    BS.word64BE
      . unSlotNo
      . bytes32RealPointSlot
      . unPerasBoostedBlock
      $ boostedBlock
  boostedBlockHashBytes =
    BS.byteStringCopy
      . BS.fromShort
      . bytes32RealPointHash
      . unPerasBoostedBlock
      $ boostedBlock
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L121-136)
```haskell
hashVRFInput ::
  ElectionId PerasBLSCrypto ->
  Nonce ->
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVRFInput roundNo epochNonce =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 32)
    $ roundNoBytes <> epochNonceBytes
 where
  roundNoBytes =
    BS.word64BE (unPerasRoundNo roundNo)
  epochNonceBytes =
    case epochNonce of
      NeutralNonce -> mempty
      Nonce h -> BS.byteStringCopy (Hash.hashToBytes h)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L251-260)
```haskell
  verifyAggregateVoteSignature
    _
    aggPk
    roundNo
    boostedBlock
    aggSig = do
      BLS.verifyWithRole @SIGN
        (unPerasBLSCryptoAggregateVoteVerificationKey aggPk)
        (hashVoteSignature roundNo boostedBlock)
        (unPerasBLSCryptoAggregateVoteSignature aggSig)
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

**File:** ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/Crypto/DSIGN.hs (L74-80)
```haskell
  -- Context required for Byron digital signatures
  --
  -- We require the the protocol magic as well as the verification key of the
  -- genesis stakeholder of which the signing node is a delegate, which is
  -- required for signing blocks.
  type ContextDSIGN ByronDSIGN = (ProtocolMagicId, VerKeyDSIGN ByronDSIGN)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-416)
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
            controlMessageSTM
      , hPerasVoteDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionOutboundTracer tracers))
            (perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasVotePoolReaderFromChainDB $ getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L241-270)
```haskell
-- It returns 'Nothing' if either of these conditions is not met.
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```
