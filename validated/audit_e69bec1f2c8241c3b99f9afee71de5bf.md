### Title
Missing Quorum Completeness Check in `EveryoneVotes` Certificate Verification Allows Under-Quorum Peras Certificate Acceptance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs`)

---

### Summary

The `implVerifyCert` function for the `EveryoneVotes` Peras voting-committee scheme verifies that each voter listed in a received certificate is a valid committee member and that the aggregate BLS signature is correct, but it never checks that the voter set is **complete** — i.e., that it contains every eligible voter. Because BLS aggregate signatures are valid for any non-empty subset of signers, an unprivileged peer can craft a `EveryoneVotesCert` containing only a single valid voter and a valid single-voter aggregate signature. The certificate passes all validation steps, is admitted to the Peras certificate pool, and can subsequently be included in a block to grant it an unearned chain-selection weight boost.

---

### Finding Description

**Root cause — missing completeness check in `implVerifyCert`**

`implVerifyCert` (lines 293–340 of `EveryoneVotes.hs`) performs two checks:

1. For each `seatIndex` in the certificate's `voters` set, it calls `getCandidateIfSeatWithinBounds` to confirm the seat exists in the stake distribution and that the voter has non-zero stake.
2. It aggregates the corresponding vote-verification keys and calls `verifyAggregateVoteSignature` to confirm the aggregate BLS signature is valid. [1](#0-0) 

What is **absent**: there is no assertion of the form

```haskell
NESet.size voters == totalEligibleVoters committee
```

The `EveryoneVotes` scheme is named and designed so that *all* eligible stake pools vote in every Peras round; a valid certificate is supposed to attest to full-committee agreement. The verification function, however, accepts any non-empty subset of valid voters whose aggregate signature checks out. A single-voter certificate is structurally indistinguishable from a full-committee certificate as far as `implVerifyCert` is concerned.

**Inbound path — `processCerts`**

Certificates arrive from remote peers via the object-diffusion mini-protocol and are processed by `processCerts`: [2](#0-1) 

`processCerts` filters out rounds already present in the DB, then calls the supplied `validateCert` (which resolves to `implVerifyCert` for `EveryoneVotes`). If all certificates in the batch pass, they are timestamped and inserted into the pool via `addCert`. No completeness check is performed at this layer either.

**Downstream use — `needCertRules` / block inclusion**

Once in the pool, the certificate is evaluated by `needCertRules`: [3](#0-2) 

The three inclusion predicates (`noCertsFromTwoRoundsAgo`, `latestCertSeenIsNotExpired`, `latestCertSeenIsNewerThanLatestCertOnChain`) are purely round-number comparisons. None of them re-examine the voter-set size. A single-voter certificate that is newer than the on-chain certificate and not expired satisfies all three rules and is included in the next forged block, granting it a Peras weight boost.

---

### Impact Explanation

An unprivileged peer who controls even one valid stake pool can cause honest nodes to accept a Peras certificate that does not represent the required full-committee consensus. The boosted block gains an unearned chain-selection advantage. Honest nodes following the Peras chain-selection rule will prefer the artificially boosted block over a legitimately heavier chain, constituting a **High-severity chain-selection bug**: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

Any peer connected to a Peras-enabled node can send crafted certificates via the object-diffusion mini-protocol. The attacker needs only:
- One valid stake pool key (to produce a valid single-voter BLS aggregate signature).
- Knowledge of the current committee's seat-index assignment (derivable from the public stake distribution).

No stake majority, no KES/VRF key compromise, and no operator privilege is required.

---

### Recommendation

Add a completeness assertion inside `implVerifyCert` immediately after the per-voter traversal:

```haskell
let totalEligible = totalEligibleVoters committee  -- count of all seats in extWFAStakeDistr
when (NESet.size voters /= totalEligible) $
  Left (InsufficientVoters (NESet.size voters) totalEligible)
```

This mirrors the fix recommended in the external report (`tokenAddress != NATIVE`): explicitly reject inputs that satisfy the structural type but violate the semantic precondition. [4](#0-3) 

---

### Proof of Concept

1. Attacker controls pool `P` with seat index `s` in the current `EveryoneVotes` committee (total eligible voters: `N > 1`).
2. Attacker calls `forgeVote witness privateKey electionId candidate` to produce a single valid `EveryoneVotesVote s electionId candidate sig`.
3. Attacker constructs `EveryoneVotesCert electionId candidate (NESet.singleton s) aggSig` where `aggSig` is the BLS aggregate of the single vote signature — a valid BLS aggregate over one key.
4. Attacker sends this certificate to an honest node via the object-diffusion mini-protocol.
5. `processCerts` invokes `implVerifyCert`:
   - `getCandidateIfSeatWithinBounds s` → succeeds (P is a valid member).
   - `nonZero voterStake` → succeeds (P has non-zero stake).
   - `aggregateVoteVerificationKeys [vk_P]` → succeeds (one key).
   - `verifyAggregateVoteSignature aggVK electionId candidate aggSig` → succeeds (valid single-voter aggregate).
6. Certificate is inserted into the Peras certificate pool.
7. The next block producer evaluates `needCert`: the certificate is not expired, is newer than the on-chain certificate, and there is no cert from two rounds ago → `IncludeCert`.
8. The block is forged with the certificate included, receiving a Peras weight boost.
9. Honest nodes following the Peras chain-selection rule prefer the boosted block, even though only 1 of N required voters attested to it. [4](#0-3) [2](#0-1) [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L293-340)
```haskell
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
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

    -- Return the list of voters attesting the election winner
    pure members
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L318-324)
```haskell
needCertRules ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
```
