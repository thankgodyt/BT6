### Title
Peras Certificate and Vote Signature Verification Bypass — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance — which applies to all `StandardHash blk` block types including production Cardano blocks — implements `validatePerasCert` as an unconditional `Right` (accepts every certificate without any cryptographic check) and implements `validatePerasVote` without verifying the BLS vote signature or VRF eligibility proof. This is the direct analog of M-18: a signed credential carries a nonce/signature field that is part of the signed data, but the validator never checks it against the current state, allowing any peer to inject forged credentials.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines two validation entry points used in the live diffusion layer:

```haskell
validatePerasCert ::
  PerasCfg blk -> PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only instance in the codebase is the catch-all degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [1](#0-0) 

`validatePerasCert` returns `Right` for **every** certificate regardless of its content. No BLS aggregate signature is verified, no round-number bound is checked, and no quorum membership is confirmed. `validatePerasVote` only checks that the claimed voter appears in the stake distribution; it never calls `verifyVoteSignature` on `pvSignature` and never verifies the VRF eligibility proof in `pvEligibilityProof`.

The concrete Peras vote type carries both fields explicitly:

```haskell
data PerasVote = PerasVote
  { pvRoundNo          :: !PerasRoundNo
  , pvBoostedBlock     :: !PerasBoostedBlock
  , pvSeatIndex        :: !PerasSeatIndex
  , pvEligibilityProof :: !PerasVoteEligibilityProof   -- VRF proof, never checked
  , pvSignature        :: !(VoteSignature PerasBLSCrypto) -- BLS sig, never checked
  }
``` [2](#0-1) 

These validators are called directly from the production diffusion inbound paths:

- `makePerasVotePoolWriterFromChainDB` / `makePerasVotePoolWriterFromVoteDB` call `validatePerasVote mkPerasParams sd vote` for every inbound vote received from a peer.
- `processCerts` calls `validatePerasCert mkPerasParams` for every inbound certificate received from a peer. [3](#0-2) [4](#0-3) 

A validated certificate is then inserted into the ChainDB via `addPerasCertAsync`, where it contributes a `perasWeight` boost to chain selection for the boosted block. [5](#0-4) 

The WFALS committee implementation shows what the correct validation path looks like — it calls `verifyVoteSignature`, `evalVRF`, and `batchVerifyVRFOutputs` — but none of this is wired into the `BlockSupportsPeras` instance used for production blocks. [6](#0-5) 

---

### Impact Explanation

An unprivileged peer connected via the Peras object-diffusion mini-protocol can:

1. **Forge a Peras certificate** for any block it chooses (including an adversarial fork tip), with any round number, and have it accepted unconditionally by `validatePerasCert`. The certificate is then stored in the ChainDB and applies a `perasWeight` boost to that block's chain-selection score.
2. **Forge Peras votes** attributed to any registered stake-pool key without possessing the corresponding BLS signing key, because `validatePerasVote` never calls `verifyVoteSignature`. Enough forged votes can trigger certificate generation internally.

Both paths allow an adversary to manipulate chain selection in favour of a non-canonical chain, constituting a **chain-selection safety failure** reachable by an unprivileged peer with no key material.

This maps to the allowed impact: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

The Peras mini-protocol infrastructure is wired into the diffusion layer and the ChainDB API. Any node that enables the Peras object-diffusion protocol (vote and certificate gossip) is immediately exposed. No key compromise, stake majority, or operator action is required — a single TCP connection to the node suffices. The only mitigating factor is that Peras may not yet be activated on mainnet; however, the code is present and reachable in the production binary.

---

### Recommendation

Replace the stub `validatePerasCert` and `validatePerasVote` implementations with real cryptographic checks before the Peras mini-protocol is enabled on any network:

- `validatePerasCert`: verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregate verification key of the declared voters, verify each non-persistent voter's VRF output via `batchVerifyVRFOutputs`, and confirm the declared voter set constitutes a valid quorum.
- `validatePerasVote`: call `verifyVoteSignature` on `pvSignature` and, for non-persistent members, verify the VRF eligibility proof in `pvEligibilityProof` via `evalVRF` before accepting the vote.

The correct logic already exists in `Ouroboros.Consensus.Committee.WFALS` (`implVerifyVote`, `implVerifyCert`) and should be connected to the `BlockSupportsPeras` instance for production block types.

---

### Proof of Concept

On a private testnet with the Peras object-diffusion protocol enabled:

1. Connect to a target node as a peer.
2. Craft a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <attacker fork tip>`. No valid BLS signature is required.
3. Send the certificate via the Peras cert-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
5. The certificate is inserted into the ChainDB via `addPerasCertAsync` and applies `perasWeight` to the attacker's fork.
6. If the boosted weight exceeds the honest chain's weight, the node switches to the attacker's fork. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-392)
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
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
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
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
```
