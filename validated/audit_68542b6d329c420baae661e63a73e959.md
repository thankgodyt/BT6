### Title
Peras Certificate Validation Bypass: Stub `validatePerasCert` Unconditionally Accepts Any Inbound Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` provides a stub `validatePerasCert` that unconditionally returns `Right` for every inbound Peras certificate, performing zero cryptographic or committee-membership checks. This stub is the **only** `BlockSupportsPeras` instance in the codebase and is wired directly into the production certificate-diffusion path (`makePerasCertPoolWriterFromChainDB`), which calls `ChainDB.addPerasCertAsync` and can trigger chain selection. An unprivileged peer can therefore inject a crafted `PerasCert` naming any block at any round, have it accepted as valid, and cause the receiving node to boost and prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

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

This is the **only** `BlockSupportsPeras` instance in the repository (confirmed by grep: only two matches in `SupportsPeras.hs` — the class definition and this universal instance). [2](#0-1) 

The degenerate `PerasCert` data type carries only a round number and a boosted block point — no aggregate signature, no voter set, no cryptographic proof of committee quorum:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound        :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [3](#0-2) 

**Production call site — `makePerasCertPoolWriterFromChainDB`:**

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
(void . ChainDB.addPerasCertAsync chainDB)
``` [4](#0-3) 

`processCerts` calls `validateCert` on every inbound certificate from a peer; if all pass (which they always do under the stub), each is timestamped and forwarded to `addCert` — here `ChainDB.addPerasCertAsync` — which can trigger a chain-selection fork switch: [5](#0-4) 

The `ChainDB` API documents that `addPerasCertAsync` "will trigger a fork switch" if the certificate makes a fork weightier than the current selection: [6](#0-5) 

**Secondary issue — `validatePerasVote` also skips signature verification:**

The degenerate `PerasVote` type carries no signature field, and `validatePerasVote` only checks stake-distribution membership, not any cryptographic proof of authorship. Any peer can impersonate any voter in the distribution; if enough fake votes accumulate to reach quorum, a fake certificate is generated internally. [7](#0-6) 

---

### Impact Explanation

Peras certificates carry a `PerasWeight` boost that is added to the chain-selection score of the boosted block. A node that accepts a forged certificate for an attacker-chosen block will treat that block's chain as heavier than it actually is, potentially switching away from the canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Ouroboros Praos/Peras.

The `ValidatedPerasCert` wrapper is the type-level "proof of validity" that downstream chain-selection code trusts. Because `validatePerasCert` always produces this wrapper unconditionally, the type-level guarantee is hollow — analogous to the external report's `burn` function accepting NFTs from any depositor without checking which depositor originally minted them.

---

### Likelihood Explanation

Any peer participating in the Peras certificate object-diffusion mini-protocol can send a `PerasCert` message. No stake, no keys, and no committee membership are required. The attacker only needs to:
1. Connect to a target node as a peer.
2. Craft a `PerasCert` with the desired `pcCertRound` and `pcCertBoostedBlock`.
3. Send it via the object-diffusion protocol.

The stub is the **only** instance in the codebase; there is no override for Cardano block types. The TODO comment and the linked issue (`cardano-peras/issues/120`) confirm the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert`: verify the aggregate BLS signature over the `(electionId, candidate)` pair against the aggregated public keys of the claimed voter set, verify each voter's committee membership and stake, and check that the total stake meets the quorum threshold. The `implVerifyCert` functions in `WFALS.hs` and `EveryoneVotes.hs` show the correct pattern. [8](#0-7) 

2. **Add a signature field to `PerasCert`** (and `PerasVote`) so that the wire format carries the cryptographic proof required for verification.

3. **Implement real vote validation** in `validatePerasVote`: verify the vote signature against the voter's public key before accepting the vote into the pool.

4. Until the above are in place, consider **gating the Peras certificate diffusion path** behind a feature flag so that the stub cannot be reached on production nodes.

---

### Proof of Concept

```
Attacker node  ──[ObjectDiffusion: PerasCert]──►  Honest node
                                                       │
                                                  processCerts
                                                       │
                                              validatePerasCert mkPerasParams cert
                                                       │
                                              always returns Right ValidatedPerasCert
                                                       │
                                              ChainDB.addPerasCertAsync chainDB cert
                                                       │
                                              chain-selection re-runs with
                                              attacker's block boosted by perasWeight
                                                       │
                                              node may switch to attacker's fork
```

Concretely:

1. Attacker identifies block `B_adv` on a minority fork.
2. Attacker constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf B_adv }`.
3. Attacker sends this certificate to the honest node via the Peras cert diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
5. `ChainDB.addPerasCertAsync` stores the certificate; chain selection adds `perasWeight` to `B_adv`'s chain score.
6. If `B_adv`'s boosted score exceeds the honest chain's score, the node switches forks.

The only deduplication guard is `Set.member roundNo certIds` — one certificate per round number. An attacker can therefore inject one forged certificate per Peras round, permanently biasing chain selection for that round. [5](#0-4) [1](#0-0)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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
