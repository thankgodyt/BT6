### Title
Peras Certificate and Vote Validation Bypass via Stub `validatePerasCert`/`validatePerasVote` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance used for all block types contains stub implementations of `validatePerasCert` and `validatePerasVote` that perform no cryptographic verification. `validatePerasCert` unconditionally returns `Right` (success) for every certificate it receives. `validatePerasVote` only checks stake-distribution membership but never verifies the BLS vote signature. Both stubs are wired directly into the production inbound ObjectDiffusion handlers (`processCerts`, `processVotes`) that process data arriving from untrusted network peers.

---

### Finding Description

The `BlockSupportsPeras` type class defines two critical validation methods:

```haskell
validatePerasCert :: PerasCfg blk -> PerasCert blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote :: PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk
                  -> Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only instance in the codebase is the catch-all degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...
    | otherwise = Left PerasValidationErr
```

`validatePerasCert` **always returns `Right`** — it never inspects the aggregate BLS signature (`pcSignature`) or the voter eligibility proofs (`pcVoters`) defined in `Ouroboros.Consensus.Peras.Cert.V1.PerasCert`. [1](#0-0) 

`validatePerasVote` only checks that the voter's key hash appears in the stake distribution map. It never calls `verifyVoteSignature` (which exists in `CryptoSupportsVoteSigning`) or verifies the VRF eligibility proof. [2](#0-1) 

These stubs are the live validators passed to the production inbound handlers. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` directly to `processCerts`, which is the function that processes every certificate batch received from a peer: [3](#0-2) 

`makePerasVotePoolWriterFromChainDB` passes `validatePerasVote mkPerasParams sd vote` to `processVotes`, which processes every vote batch received from a peer: [4](#0-3) 

`processCerts` and `processVotes` are the terminal inbound handlers: any certificate or vote that is not already in the local DB and passes the stub validator is immediately timestamped and committed to the `ChainDB` or `PerasVoteDB`/`PerasCertDB`. [5](#0-4) 

The `PerasVoteDB.implAddVote` implementation also carries its own TODO noting that non-trivial validation logic is still missing: [6](#0-5) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate and vote signature validation enabling unauthorized certificate acceptance.**

A Peras certificate carries an aggregate BLS signature over `(roundNo, boostedBlock)` and voter eligibility proofs. Without verifying this signature, any peer can craft a `PerasCert` for an arbitrary `(roundNo, block)` pair and have it accepted by the node. Once accepted, the certificate is stored in the `PerasCertDB`/`ChainDB` and used by chain-selection logic to apply a `vpcCertBoost` weight to the boosted block. This allows an attacker to:

1. **Boost an adversarial chain**: inject a certificate for a round that boosts a minority or adversarial fork, causing the honest node to prefer that fork over the canonical chain.
2. **Suppress legitimate quorum**: inject a certificate for a round pointing to a different block before the honest quorum certificate arrives; since the DB deduplicates by round number, the legitimate certificate for that round is silently dropped (`PerasCertAlreadyInDB`).
3. **Manufacture fake quorum from votes**: inject votes for any voter key that appears in the stake distribution (no signature check), accumulate enough stake-weighted votes to trigger `forgePerasCert`, and produce a fraudulent certificate that boosts the wrong block.

---

### Likelihood Explanation

Any unprivileged peer connected via the Peras ObjectDiffusion mini-protocol can send crafted certificates or votes. No key material, stake, or special privilege is required — only a valid TCP connection to the node. The attack is deterministic and requires no brute force. The only prerequisite is that the Peras protocol extension is active on the network.

---

### Recommendation

1. **Implement `validatePerasCert`** to verify the aggregate BLS signature over `(roundNo, boostedBlock)` using the committee's aggregate verification key, and to verify each voter's eligibility proof. The cryptographic primitives already exist in `Ouroboros.Consensus.Peras.Crypto.BLS` (`verifyVoteSignature`, `evalVRF`). [7](#0-6) 

2. **Implement `validatePerasVote`** to call `verifyVoteSignature` (for persistent members) and `evalVRF` + `localSortitionNumSeats` (for non-persistent members), mirroring the logic already present in `implVerifyVote` in `Ouroboros.Consensus.Committee.WFALS`. [8](#0-7) 

3. Remove the catch-all `instance StandardHash blk => BlockSupportsPeras blk` and replace it with a concrete Cardano-specific instance that performs full cryptographic validation, as tracked in https://github.com/tweag/cardano-peras/issues/120.

---

### Proof of Concept

**Certificate injection (no keys needed):**

```
peer connects via ObjectDiffusion mini-protocol
→ sends PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlock }
   (with any bytes in pcSignature / pcVoters fields)
→ processCerts calls validatePerasCert mkPerasParams cert
→ validatePerasCert returns Right (unconditionally)
→ cert is stored in ChainDB for round R
→ chain selection applies vpcCertBoost weight to adversarialBlock
→ node switches to adversarial fork
```

**Vote injection to manufacture quorum:**

```
peer connects via ObjectDiffusion mini-protocol
→ sends N PerasVote { pvVoteRound = R, pvVoteBlock = adversarialBlock,
                      pvVoteVoterId = legitimatePoolKeyHash_i }
   for i = 1..N (key hashes scraped from on-chain stake distribution)
→ processVotes calls validatePerasVote mkPerasParams stakeDistr vote
→ validatePerasVote finds each key in stakeDistr, returns Right with real stake weight
   (no BLS signature checked)
→ votes accumulate in PerasVoteDB; once total stake > quorum threshold,
   forgePerasCert is called and a fraudulent certificate is stored
→ chain selection boosts adversarialBlock
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L162-170)
```haskell
  verifyVoteSignature
    pk
    roundNo
    boostedBlock
    (PerasBLSCryptoVoteSignature sig) =
      BLS.verifyWithRole @SIGN
        pk
        (hashVoteSignature roundNo boostedBlock)
        sig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-390)
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
```
