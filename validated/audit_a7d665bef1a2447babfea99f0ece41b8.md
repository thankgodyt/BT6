### Title
Peras Certificate and Vote Signature Verification Bypass Allows Unprivileged Peer to Inject Fake Chain-Weight Boosts - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance implements `validatePerasCert` and `validatePerasVote` as stubs that perform no cryptographic verification. Both functions are wired directly into the production node-to-node Peras diffusion handlers. An unprivileged peer can send crafted `PerasCert` or `PerasVote` objects that are unconditionally accepted, allowing injection of fake Peras weight boosts that corrupt chain selection on any receiving node.

### Finding Description

The `BlockSupportsPeras` typeclass defines two validation entry points consumed by the inbound diffusion pipeline:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk ->
  PerasVoteStakeDistr ->
  PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only concrete implementation in the codebase is the default instance for `StandardHash blk`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

`validatePerasCert` accepts every inbound certificate unconditionally — no BLS aggregate signature check, no voter eligibility check, no quorum check. [1](#0-0) 

`validatePerasVote` only checks that the voter ID appears in the stake distribution; it never verifies the BLS vote signature or the VRF eligibility proof:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

These stubs are consumed directly by the production pool writers:

`makePerasCertPoolWriterFromChainDB` passes `(validatePerasCert mkPerasParams)` as the validation callback for every inbound certificate batch. [3](#0-2) 

`makePerasVotePoolWriterFromChainDB` passes `(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)` for every inbound vote batch. [4](#0-3) 

Both pool writers are wired into the live node-to-node handlers in `mkHandlers`: [5](#0-4) 

The codebase does contain a complete, correct BLS verification stack — `verifyAggregateVoteSignature`, `batchVerifyVRFOutputs`, `linearizeAndVerifyVRFs` — all implemented and tested in `WFALS.hs`, `EveryoneVotes.hs`, and `Peras/Crypto/BLS.hs`. The domain-separation mechanism (`KeyScope`, `HasBLSContext`, `signWithRole`/`verifyWithRole`) is also fully implemented. [6](#0-5) 

The root cause is that the stub `BlockSupportsPeras` instance — the only instance in the codebase — never calls any of this verification logic.

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or adversarially-boosted chain.**

Peras certificates grant a configurable weight boost (`perasWeight`, default 15) to the block they reference. The `PerasCertDB` and `ChainDB` use these boosts during chain selection. Because `validatePerasCert` returns `Right` for any input, an attacker can:

1. Craft a `PerasCert` naming any block point and any round number.
2. Send it via the Peras cert diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert cert 15)`.
4. The fake certificate is stored and its boost is applied to chain selection.

For votes, an attacker who knows any valid voter ID (the stake distribution is public) can forge votes for arbitrary blocks in arbitrary rounds. If enough fake votes are injected to reach the quorum threshold, `implAddVote` in `PerasVoteDB` will forge a certificate for the attacker's chosen block. [7](#0-6) 

### Likelihood Explanation

**High.** The attack requires only a standard peer connection — no keys, no stake, no privileged access. The Peras cert and vote diffusion mini-protocols are enabled in `mkHandlers` for all node-to-node connections. The attacker needs only to serialize a valid CBOR-encoded `PerasCert` or `PerasVote` structure (both serialization formats are fully specified in `Peras/Cert/V1.hs` and `Peras/Vote/V1.hs`) and send it over the wire. [8](#0-7) [9](#0-8) 

### Recommendation

Replace the stub `validatePerasCert` and `validatePerasVote` implementations with calls to the existing `verifyCert` / `verifyVote` logic from the `VotingCommittee` typeclass (already implemented for both `WFALS` and `EveryoneVotes`). The conversion layer in `Peras/Voting/Committee.hs` (`fromPerasCert`, `fromPerasVote`) already exists to bridge the concrete wire types to the abstract committee types. Until the full committee selection plumbing is in place, the node should refuse to accept any Peras certificate or vote rather than accept all of them unconditionally. [10](#0-9) 

### Proof of Concept

**Fake certificate injection (no keys required):**

```
1. Attacker connects to a Cardano node as a peer (standard NTN connection).
2. Attacker serializes a PerasCert (CBOR list of 4):
     pcRoundNo       = <any PerasRoundNo not yet in the DB>
     pcBoostedBlock  = <point of any block the attacker wants to boost>
     pcVoters        = <empty or minimal PerasCertVoters map>
     pcSignature     = <32 zero bytes — any bytes accepted>
3. Attacker sends the cert via the PerasCertDiffusion mini-protocol.
4. processCerts calls validatePerasCert mkPerasParams cert
   → returns Right (ValidatedPerasCert cert 15)   -- no signature check
5. The cert is stored in PerasCertDB with boost weight 15.
6. Chain selection now treats the attacker's chosen block as having
   15 extra weight units, potentially overriding the honest chain tip.
```

The `validatePerasCert` stub at lines 353–358 of `SupportsPeras.hs` is the single necessary and sufficient vulnerable step; no other code path can reject the certificate before it reaches the DB. [11](#0-10) [12](#0-11)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-409)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L196-254)
```haskell
-- | Role-separated BLS contexts for  signatures
class HasBLSContext (r :: KeyRole) where
  blsCtx :: Proxy r -> KeyScope -> BLS12381SignContext

instance HasBLSContext SIGN where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VOTE:" <> keyScope <> ":V0")
      }

instance HasBLSContext VRF where
  blsCtx _ keyScope =
    minSigSignatureDST
      { blsSignContextAug =
          Just ("VRF:" <> keyScope <> ":V0")
      }

instance HasBLSContext POP where
  blsCtx _ keyScope =
    minSigPoPDST
      { blsSignContextAug =
          Just ("POP:" <> keyScope <> ":V0")
      }

-- | Sign a message with a  private key, producing a  signature
signWithRole ::
  forall r msg.
  ( SignableRepresentation msg
  , HasBLSContext r
  ) =>
  PrivateKey r ->
  msg ->
  Signature r
signWithRole sk msg =
  Signature
    { unSignature =
        signDSIGN
          (blsCtx (Proxy @r) (privateKeyScope sk))
          msg
          (unPrivateKey sk)
    }

-- | Verify a  signature on a message with a  public key
verifyWithRole ::
  forall r msg.
  ( SignableRepresentation msg
  , HasBLSContext r
  ) =>
  PublicKey r ->
  msg ->
  Signature r ->
  Either String ()
verifyWithRole pk msg (Signature sig) =
  verifyDSIGN
    (blsCtx (Proxy @r) (publicKeyScope pk))
    (unPublicKey pk)
    msg
    sig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-237)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-85)
```haskell
-- | Concrete Peras certificates using BLS signatures
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

instance FromCBOR PerasCert where
  fromCBOR = do
    decodeListLenOf 4
    pcRoundNo <- fromCBOR
    pcBoostedBlock <- fromCBOR
    pcVoters <- fromCBOR
    pcSignature <- fromCBOR
    pure
      PerasCert
        { pcRoundNo
        , pcBoostedBlock
        , pcVoters
        , pcSignature
        }

instance ToCBOR PerasCert where
  toCBOR cert =
    encodeListLen 4
      <> toCBOR (pcRoundNo cert)
      <> toCBOR (pcBoostedBlock cert)
      <> toCBOR (pcVoters cert)
      <> toCBOR (pcSignature cert)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-76)
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

instance FromCBOR PerasVote where
  fromCBOR = do
    decodeListLenOf 5
    pvRoundNo <- fromCBOR
    pvBoostedBlock <- fromCBOR
    pvSeatIndex <- fromCBOR
    pvEligibilityProof <- fromCBOR
    pvSignature <- fromCBOR
    pure
      PerasVote
        { pvRoundNo
        , pvBoostedBlock
        , pvSeatIndex
        , pvEligibilityProof
        , pvSignature
        }

instance ToCBOR PerasVote where
  toCBOR vote =
    encodeListLen 5
      <> toCBOR (pvRoundNo vote)
      <> toCBOR (pvBoostedBlock vote)
      <> toCBOR (pvSeatIndex vote)
      <> toCBOR (pvEligibilityProof vote)
      <> toCBOR (pvSignature vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Committee.hs (L109-157)
```haskell
  fromPerasVote = \case
    V1.PerasVote electionId candidate seatIndex proof sig -> do
      let seatIndex' = fromPerasSeatIndex seatIndex
      case proof of
        V1.PersistentPerasVoteEligibilityProof ->
          pure $
            WFALSPersistentVote
              seatIndex'
              electionId
              candidate
              sig
        V1.NonPersistentPerasVoteEligibilityProof vrfOutput ->
          pure $
            WFALSNonPersistentVote
              seatIndex'
              electionId
              candidate
              vrfOutput
              sig

-- 'V1.PerasCert's are compatible with 'WFALS' as long as we make sure to avoid
-- overflowing the `Word16` seat index of each voter.
instance
  PerasCertCompatibleWithVotingCommittee
    V1.PerasCert
    PerasBLSCrypto
    WFALS
  where
  toPerasCert = \case
    WFALSCert electionId candidate voters sig -> do
      voters' <- toPerasCertVoters voters
      pure $
        V1.PerasCert
          { V1.pcRoundNo = electionId
          , V1.pcBoostedBlock = candidate
          , V1.pcVoters = voters'
          , V1.pcSignature = sig
          }

  fromPerasCert = \case
    V1.PerasCert electionId candidate voters sig -> do
      let voters' = fromPerasCertVoters voters
      pure $
        WFALSCert
          electionId
          candidate
          voters'
          sig

```
