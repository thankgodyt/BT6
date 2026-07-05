### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates into Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound `PerasCert` without performing any cryptographic or quorum check. The production node wires this stub directly into the live Peras certificate diffusion inbound handler, so any unprivileged peer can send a crafted `PerasCert` pointing to an arbitrary block, have it stored in the `ChainDB`, and have it applied as a Peras boost in chain selection, with no signature, voter eligibility, or quorum verification whatsoever.

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:**

The universal `BlockSupportsPeras` instance (the only instance in the codebase) implements certificate validation as:

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

This is a catch-all instance (`instance StandardHash blk => BlockSupportsPeras blk`) that applies to every block type, including production Cardano blocks. No more-specific instance exists in the repository. [2](#0-1) 

**Production inbound path — `makePerasCertPoolWriterFromChainDB` calls this stub:**

`processCerts` is the inbound validation gate. It calls the supplied `validateCert` function on every received certificate. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` — the unconditional stub — as that gate:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

**Live node wiring — `hPerasCertDiffusionClient` uses this writer directly:**

The production `NodeToNode` handler wires `makePerasCertPoolWriterFromChainDB` into the live Peras certificate diffusion inbound miniprotocol:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**End-to-end exploit path:**

1. Attacker connects to a Peras-enabled node as a normal peer (no privilege required).
2. Attacker sends a crafted `PerasCert` via the `PerasCertDiffusion` miniprotocol with `pcCertRound` set to the current round and `pcCertBoostedBlock` pointing to the attacker's chosen block (e.g., a fork tip).
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → unconditionally returns `Right (ValidatedPerasCert cert boost)`.
4. The certificate is timestamped and passed to `ChainDB.addPerasCertAsync`.
5. The ChainDB applies the Peras boost to the attacker-chosen block during chain selection.
6. The honest node may switch to the attacker's fork because it now carries a Peras certificate boost. [5](#0-4) 

**Contrast with vote validation:** The analogous `validatePerasVote` at least checks stake distribution membership (though it lacks signature verification). The production node additionally hardcodes an empty stake distribution for votes, causing all votes to be rejected. Certificates have no such backstop — `validatePerasCert` is purely unconditional. [6](#0-5) [7](#0-6) 

### Impact Explanation

**Critical/High — Bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain selection manipulation.**

Any unprivileged peer can inject a `PerasCert` for any block in any round. The receiving node will store it as a `ValidatedPerasCert` with full Peras boost weight and apply it in chain selection. This allows an adversary to:

- Boost an adversarial fork to make honest nodes prefer it over the canonical chain.
- Suppress the boost of the honest chain by injecting a conflicting certificate for a different block in the same round (since the DB deduplicates by round number, the first accepted certificate wins).
- Cause irreversible chain selection divergence between nodes that receive the crafted certificate and those that do not.

This directly matches the allowed impact: *"Bypass of... Peras voting or certificate checks... that enables unauthorized block, vote, or certificate acceptance"* and *"Chain selection... bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

**High.** The attacker preconditions are minimal: establish a standard peer-to-peer connection to a Peras-enabled node. No keys, no stake, no privileged access are required. The `PerasCertDiffusion` miniprotocol is part of the standard node-to-node protocol bundle and is reachable by any peer that negotiates a compatible `NodeToNodeVersion`. The crafted certificate requires only valid CBOR encoding of a `PerasRoundNo` and a `Point blk` — both are trivially constructable.

### Recommendation

Replace the unconditional stub with a real implementation that:

1. Verifies the aggregate BLS signature in `pcSignature` against the declared voter set in `pcVoters`.
2. Checks each declared voter's eligibility (seat index within bounds, persistent/non-persistent membership, VRF proof for non-persistent voters) against the committee derived from the current epoch's stake distribution.
3. Verifies that the total voting weight of the declared voters meets the Peras quorum threshold.
4. Rejects any certificate that fails any of these checks.

Until the real implementation is ready, the stub should be replaced with `Left PerasValidationErr` (reject all) rather than `Right` (accept all), consistent with the fail-safe principle. The existing `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert` implementations in the `Committee` modules provide the correct structural template. [8](#0-7) 

### Proof of Concept

**Setup:** A Peras-enabled node running with the production `NodeToNode` handlers.

**Steps:**

1. Connect to the target node as a peer supporting `PerasCertDiffusion`.
2. Construct a `PerasCert` with:
   - `pcCertRound = <current Peras round>`
   - `pcCertBoostedBlock = <hash and slot of attacker's chosen fork tip>`
3. Advertise the certificate's round number via the `ObjectDiffusion` `MsgReplyIds` message.
4. When the node requests the certificate body via `MsgRequestObjects`, reply with the crafted `PerasCert`.
5. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right (ValidatedPerasCert cert boost)` unconditionally.
6. `ChainDB.addPerasCertAsync` stores the certificate and triggers chain selection.
7. **Expected outcome:** The node's chain selection now applies a Peras boost to the attacker-chosen block. If that block is on a fork, the node may switch to the fork. Nodes that did not receive the crafted certificate will not apply the boost, causing a chain selection divergence between honest nodes. [1](#0-0) [9](#0-8) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
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
