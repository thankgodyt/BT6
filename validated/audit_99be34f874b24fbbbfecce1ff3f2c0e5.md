### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Chain-Selection Manipulation by an Unprivileged Peer - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementation of `validatePerasCert` in `BlockSupportsPeras` is a stub that unconditionally returns `Right ValidatedPerasCert` for every inbound certificate, performing zero cryptographic or structural checks. Because the Peras certificate diffusion miniprotocol is fully wired into the production node-to-node stack and feeds directly into `ChainDB.addPerasCertAsync`, any unprivileged peer can inject arbitrary `PerasCert` objects that are accepted as valid, stored in the `PerasCertDB`, and used to apply Peras weight boosts during chain selection. This is the consensus-layer analog of the `transferTo`/`tx.origin` pattern: a function that is supposed to enforce authorization skips all checks, allowing an external actor to trigger privileged state changes on behalf of the node.

---

### Finding Description

**Root cause — stub validator always returns `Right`:** [1](#0-0) 

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

Every `PerasCert blk` received from any peer is wrapped in `Right ValidatedPerasCert` with a non-zero `vpcCertBoost`. No signature, no quorum check, no round-number sanity, no issuer eligibility — nothing.

**Inbound diffusion path wires this stub into the live node:** [2](#0-1) 

The `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which passes `validatePerasCert mkPerasParams` as the validation function: [3](#0-2) 

`processCerts` calls this validator for every inbound cert and, on `Right`, immediately calls `addPerasCertAsync chainDB`: [4](#0-3) 

**Accepted certs affect chain selection via Peras weight boosts:** [5](#0-4) 

`addPerasCertAsync` stores the cert and, if it makes a fork heavier than the current selection, triggers a chain switch. The `vpcCertBoost` value assigned by the stub (`perasWeight params`) is the weight applied.

**End-to-end exploit path:**

1. Attacker connects to a victim node via the standard node-to-node protocol.
2. Attacker sends a crafted `PerasCert` (arbitrary round number, arbitrary boosted block hash) via the `PerasCertDiffusion` miniprotocol.
3. `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert` (stub, always `Right`) → `addPerasCertAsync`.
4. The cert is stored in `PerasCertDB` with a non-zero weight boost.
5. `ChainDB` re-evaluates chain selection using the boosted weight; if the attacker's target block is on a fork, the node may switch to that fork.

---

### Impact Explanation

**Allowed impact class: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

A single connected peer can inject a `PerasCert` that boosts an arbitrary block on a minority fork. Because `validatePerasCert` performs no checks, the attacker does not need any stake, keys, or quorum. The node will apply the weight boost and, if the boosted fork becomes heavier than the current selection, switch to it. This breaks the Peras chain-selection invariant (only legitimately certified blocks should receive weight boosts) and can cause permanent divergence from the honest chain.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` miniprotocol is fully wired into the production node-to-node stack. Any peer that can establish a connection — no stake, no keys, no special privileges required — can send a `PerasCert` message. The stub is the *only* validation gate between the network and the `PerasCertDB`. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete implementation shipped in the production codebase.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over the claimed voter set.
2. Checks that the voter set meets the quorum threshold against the epoch's stake distribution.
3. Validates each voter's eligibility (persistent or non-persistent committee membership) using the same `VotingCommittee` machinery already implemented in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes`.
4. Verifies the round number is within the valid range for the current chain tip.

Until the real implementation is ready, the stub should be changed to `Left PerasValidationErr` (safe-fail, reject all) rather than `Right` (accept all), mirroring the safe-fail behavior already applied to vote validation via the empty stake distribution. [6](#0-5) 

---

### Proof of Concept

**Attacker preconditions:** A node that can establish a node-to-node TCP connection to the victim. No stake, no keys, no privileged access required.

**Steps:**

1. Establish a node-to-node connection and negotiate the `PerasCertDiffusion` miniprotocol.
2. Construct a `PerasCert blk` with:
   - `pcCertRound` = any `PerasRoundNo`
   - `pcCertBoostedBlock` = the `Point blk` of a block on a minority fork that the attacker wants the victim to adopt.
3. Send the cert via the `ObjectDiffusion` protocol message.
4. On the victim node, `processCerts` calls `validatePerasCert mkPerasParams cert` which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }`.
5. `addPerasCertAsync chainDB` stores the cert and triggers chain selection.
6. If the boosted fork's weight now exceeds the current selection's weight, the victim switches to the attacker's preferred fork.

**Expected outcome:** The victim node adopts a non-canonical chain without any legitimate quorum of stake pool operators having voted for it, violating the Peras safety guarantee. [1](#0-0) [4](#0-3) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-459)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
      PerasCertTicketNo ->
      STM m (Map PerasCertTicketNo (m (WithArrivalTime (ValidatedPerasCert blk))))
  -- ^ Get all known Peras certs with a ticket number strictly greater than the
  -- given one, in ascending order. The values are 'm' actions to allow
  -- implementations with on-disk storage.
  , getPerasCertIds :: STM m (Set PerasRoundNo)
  -- ^ Get the set of all Peras certificate round numbers currently in the
  -- database.
  , addPerasVoteWithAsyncCertHandling ::
      WithArrivalTime (ValidatedPerasVote blk) ->
      m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
  -- ^ Add a Peras vote to the vote database, returning the result of the
  -- vote addition. If a certificate is produced in the process (quorum
  -- reached), it will be added via 'addPerasCertAsync' under the hood, in
  -- which case the corresponding promise will be returned.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-515)
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
```
