### Title
`validatePerasCert` Accepts All Inbound Peras Certificates Without Cryptographic Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate as valid, performing zero cryptographic or structural checks. The `PerasCert blk` data type carries no signature field. Any unprivileged peer reachable via the `PerasCertDiffusion` mini-protocol can send a crafted certificate that passes validation, is stored in the `PerasCertDB`, and is enqueued for chain selection, where it applies a Peras weight boost to an attacker-chosen block.

---

### Finding Description

The degenerate `BlockSupportsPeras` instance — the only instance in the codebase, used by all block types including `CardanoBlock` — defines `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

The `PerasCert blk` data type itself carries only a round number and a boosted block point — no signature, no eligibility proof, no voter set:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

This is structurally different from the committee-level `Cert` types (`WFALSCert`, `EveryoneVotesCert`) which carry aggregate BLS signatures and VRF outputs and are verified by `implVerifyCert`. [3](#0-2) 

The production inbound handler for the `PerasCertDiffusion` mini-protocol is wired directly to `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on every received certificate before storing it:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [4](#0-3) 

Once a certificate passes `validatePerasCert` (which it always does), it is stored and enqueued for chain selection via `addPerasCertAsync`: [5](#0-4) 

The `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the Peras weight boost applied to the boosted block during chain selection.

A secondary, partially-mitigated analog exists in `validatePerasVote`: it only checks stake-distribution membership for the claimed `pvVoteVoterId`, with no signature field on `PerasVote blk` and no cryptographic proof that the sender controls the corresponding private key. [6](#0-5) 

The production vote inbound handler currently passes an empty stake distribution (`pure (PerasVoteStakeDistr mempty)`), causing all votes to be rejected — but this is an acknowledged placeholder, not a security fix:

```haskell
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [7](#0-6) 

No such mitigation exists for certificates.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

An attacker sends a crafted `PerasCert` naming any block point as `pcCertBoostedBlock`. `validatePerasCert` returns `Right` unconditionally. The certificate is stored and enqueued for chain selection. Chain selection applies `perasWeight params` as a weight boost to the attacker-chosen block, potentially causing the honest node to prefer a fork that would otherwise be rejected. Because the boost is applied without any check that a legitimate quorum of committee members actually voted for that block, the Peras weight mechanism — designed to strengthen finality — is turned into a chain-selection manipulation primitive accessible to any peer.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` mini-protocol is enabled in the production node-to-node handler bundle and is reachable by any connected peer without authentication. The attack requires only constructing a valid CBOR-encoded `PerasCert` (two fields: a round number and a block point), which is trivially achievable. No stake, no keys, and no prior knowledge of the committee are required. The code path from receipt to chain-selection enqueue is direct and has no intervening guards.

---

### Recommendation

1. Add a cryptographic signature field to `PerasCert blk` (analogous to the `AggregateVoteSignature` in `WFALSCert`) and implement `validatePerasCert` to verify it against the committee's aggregate verification key for the claimed round, mirroring `implVerifyCert` in `Committee/WFALS.hs`.
2. Add a signature field to `PerasVote blk` and implement `validatePerasVote` to verify it using `verifyVoteSignature` against the public key of the claimed `pvVoteVoterId`, mirroring `implVerifyVote`.
3. Until proper validation is in place, gate the `PerasCertDiffusion` inbound handler so that received certificates are dropped rather than accepted unconditionally.

---

### Proof of Concept

1. Connect to a target node as a peer via the `PerasCertDiffusion` mini-protocol.
2. Encode a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a block on a competing fork>`.
3. Send the certificate via the `ObjectDiffusion` protocol.
4. The node calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is stored and enqueued via `addPerasCertAsync` → `addPerasCertToQueue` → `chainSelSync`.
6. Chain selection applies the Peras weight boost to the attacker-chosen block, potentially causing the node to switch to the attacker's preferred fork. [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-329)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-495)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-328)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue

-- | Add a Peras vote to the VoteDB contained in the ChainDB, and if this
-- results in a new cert being generated, add that cert /asynchronously/ to
-- the ChainDB as well.
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
