### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates, Bypassing Committee Membership and Signature Checks — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate without performing any cryptographic verification, committee membership check, or signature validation. This function is invoked directly from the production inbound certificate handling path (`processCerts` inside `makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can inject a crafted `PerasCert` naming an arbitrary boosted block; the certificate will be accepted, stored in the ChainDB, and used to apply a Peras weight boost during chain selection, potentially causing honest nodes to prefer an adversarial chain.

---

### Finding Description

**Root cause — unconditional acceptance in `validatePerasCert`:**

The catch-all `BlockSupportsPeras` instance (the only instance present in the codebase) implements `validatePerasCert` as a stub that always succeeds:

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

No committee membership is checked, no aggregate BLS signature is verified, and no VRF eligibility proof is inspected. The `ValidatedPerasCert` wrapper that downstream code treats as proof of validity is produced for every input unconditionally.

**Production call site — `processCerts` / `makePerasCertPoolWriterFromChainDB`:**

The production inbound certificate writer passes this stub directly as the validation callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate not already in the DB; if all pass (they always do), each is timestamped and added via `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

**Network entry point — `hPerasCertDiffusionClient` in `NodeToNode`:**

`makePerasCertPoolWriterFromChainDB` is wired directly into the `PerasCertDiffusion` miniprotocol handler that processes every inbound certificate batch from any connected peer:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**Analog to the external report's vulnerability class:**

The external report describes a state-transition authorization check that uses a *stored identity* (`claim.initiator`) which can become stale when the role is reassigned. The analog here is the *stored committee context* (`VotingCommittee`, built from epoch nonce + stake distribution) that is supposed to be checked against every inbound certificate to confirm the signers were legitimate committee members for that election round. The check is entirely absent: the stored committee identity is never consulted during inbound certificate processing, so any peer can present a certificate claiming to represent any committee decision.

The `InterEpochVotingCommittee` structure and `getVotingCommitteeForElection` were designed to handle exactly this cross-epoch lookup, but `getVotingCommitteeForElection` is also unimplemented:

```haskell
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
``` [5](#0-4) 

The full committee verification logic (`verifyVote`, `verifyCert` in `WFALS` and `EveryoneVotes`) exists and is correct in isolation, but is never invoked on the inbound network path. [6](#0-5) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance.**

An accepted forged certificate is stored in the ChainDB and contributes a `PerasWeight` boost to the block it names during chain selection:

```haskell
vpcCertBoost = perasWeight params
``` [7](#0-6) 

Chain selection uses `preferAnchoredCandidate` with the live `PerasWeightSnapshot` derived from stored validated certificates:

```haskell
assert (all (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . fst) candidates)
``` [8](#0-7) 

A peer with no stake can inject a certificate boosting an adversarial block, causing honest nodes to assign it a higher chain-selection weight than the honest chain. This is a direct chain-selection safety failure: an unprivileged peer can make an honest node prefer a non-canonical chain by fabricating Peras weight.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` miniprotocol is enabled for every node-to-node connection. No stake, no key material, and no prior relationship with the target node is required. The attacker only needs to connect as a peer and send a well-formed CBOR-encoded `PerasCert` with the desired `pcCertRound` and `pcCertBoostedBlock`. The stub validation will accept it unconditionally.

---

### Recommendation

1. **Short term**: Replace the stub `validatePerasCert` with a call to the actual committee verification logic (`verifyCert` from `WFALS` or `EveryoneVotes`) using the correct `VotingCommittee` for the certificate's election round. Until this is done, inbound Peras certificates should be rejected at the network boundary rather than accepted unconditionally.

2. **Long term**: Implement `getVotingCommitteeForElection` in `AcrossEpochs.hs` so that certificates from the previous epoch can be validated against the correct stored committee context, mirroring the cross-epoch committee-identity lookup that the module was designed to provide.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a node with Peras enabled.
2. Connect as an unprivileged peer via the `PerasCertDiffusion` miniprotocol.
3. Send a `PerasCert` message with:
   - `pcCertRound` = any valid round number not yet in the DB,
   - `pcCertBoostedBlock` = the point of an adversarial block on a fork.
4. Observe via tracing that `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
5. The certificate is stored via `ChainDB.addPerasCertAsync`.
6. On the next chain selection cycle, `getPerasWeightSnapshot` returns a snapshot containing the forged certificate's boost for the adversarial block.
7. `preferAnchoredCandidate` now assigns the adversarial candidate a higher weight, causing the node to switch to the adversarial fork.

The decisive code path is:

```
peer → PerasCertDiffusion miniprotocol
  → objectDiffusionInbound (NodeToNode.hs:375)
  → makePerasCertPoolWriterFromChainDB (PerasCert.hs:118)
  → processCerts (PerasCert.hs:156)
  → validatePerasCert mkPerasParams cert  ← always Right (SupportsPeras.hs:353)
  → ChainDB.addPerasCertAsync
  → chain selection uses forged boost weight
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L69-74)
```haskell
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L238-239)
```haskell
      assert (all ((curpt ==) . castPoint . AF.anchorPoint . fst) candidates) $
        assert (all (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . fst) candidates) $ do
```
