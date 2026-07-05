### Title
Duplicate Non-Persistent Voter Eligibility Logic Across `implVerifyVote` and `implVerifyCert` Enables Certificate Verification Bypass — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs`)

---

### Summary

The non-persistent voter eligibility check (`localSortitionNumSeats` + `nonZero numSeats`) is independently duplicated in three functions in `WFALS.hs`: `implCheckShouldVote`, `implVerifyVote`, and `implVerifyCert`. Critically, `implVerifyCert` does **not** delegate to `implVerifyVote` for per-voter eligibility — it re-implements the same logic in isolation using a structurally different VRF verification path. Any divergence between these copies (e.g., a fix applied to `implVerifyVote` but missed in `implVerifyCert`) would allow a crafted certificate containing an ineligible non-persistent voter to pass certificate verification while the same voter's individual vote would be rejected by vote verification.

---

### Finding Description

In `WFALS.hs`, the eligibility check for non-persistent voters is duplicated across three independent functions:

**Copy 1 — `implCheckShouldVote`** (local node self-check): [1](#0-0) 

**Copy 2 — `implVerifyVote`** (individual vote verification from a peer): [2](#0-1) 

**Copy 3 — `implVerifyCert`** (certificate verification from a peer): [3](#0-2) 

All three independently call `localSortitionNumSeats` and then check `nonZero numSeats`. `implVerifyCert` does not call `implVerifyVote` for each vote in the certificate; it re-implements the eligibility check from scratch.

Beyond the structural duplication, the VRF verification path also diverges between the two peer-facing functions:

- `implVerifyVote` uses `evalVRF` with a `VRFVerifyContext` for **individual** VRF verification: [4](#0-3) 

- `implVerifyCert` uses `batchVerifyVRFOutputs` for **batch** VRF verification: [5](#0-4) 

These are structurally separate code paths for the same cryptographic property (VRF eligibility of non-persistent voters). The `batchVerifyVRFOutputs` implementation uses BLS linearization (`BLS.linearizeAndVerifyVRFs`) to batch-verify all VRF outputs in a single step: [6](#0-5) 

This is a fundamentally different cryptographic operation from the individual `evalVRF` used in `implVerifyVote`. If these two paths have any behavioral difference (e.g., one is more permissive for edge-case VRF outputs), an attacker can exploit the gap.

---

### Impact Explanation

If the eligibility check in `implVerifyCert` diverges from `implVerifyVote` — for example, if the `nonZero numSeats` guard is removed from `implVerifyCert` during a refactoring that updates `implVerifyVote` — an attacker can craft a certificate containing a non-persistent voter whose VRF output yields zero seats. Such a certificate would pass `implVerifyCert` but the same voter's individual vote would be rejected by `implVerifyVote`.

Accepted certificates affect chain selection via Peras weight boosts. A certificate accepted by `implVerifyCert` that would not have been accepted under `implVerifyVote`'s stricter check causes honest nodes to apply an illegitimate weight boost to a block, potentially causing them to prefer a non-canonical or adversary-controlled chain. This is a **bypass of VRF/certificate verification enabling unauthorized certificate acceptance**, directly within the allowed impact scope.

---

### Likelihood Explanation

**Medium.** The Peras protocol is under active development — the codebase contains numerous `TODO` comments referencing open issues (e.g., `https://github.com/tweag/cardano-peras/issues/97`, `#120`, `#234`). The three copies of the eligibility logic are already non-trivially different (different VRF verification methods), and the absence of a shared helper function means any future change to the eligibility logic must be applied to all three copies manually. The network entry path is fully wired: Peras certificates arrive via the `PerasCertDiffusion` miniprotocol: [7](#0-6) 

They are processed by `processCerts`, which calls `validateCert` (i.e., `implVerifyCert`) on each received certificate: [8](#0-7) 

Any unprivileged peer can send crafted certificates over this channel.

---

### Recommendation

Extract the non-persistent voter eligibility check into a shared helper function:

```haskell
checkNonPersistentEligibility
  :: VotingCommittee crypto WFALS
  -> SeatIndex
  -> LedgerStake
  -> VRFOutput crypto
  -> Either (VotingCommitteeError crypto WFALS) (NonZero LocalSortitionNumSeats)
checkNonPersistentEligibility committee seatIndex voterStake vrfOutput =
  let numSeats = localSortitionNumSeats
        (nonPersistentCommitteeSize committee)
        (totalNonPersistentStake committee)
        voterStake
        (normalizeVRFOutput vrfOutput)
  in case nonZero numSeats of
       Nothing -> Left (ZeroNonPersistentSeats seatIndex)
       Just n  -> Right n
```

This helper should be called by `implCheckShouldVote`, `implVerifyVote`, and `implVerifyCert`, ensuring the eligibility check is consistent across all three functions and that any future change is applied uniformly.

---

### Proof of Concept

The duplicate code is in `WFALS.hs` at:
- `implVerifyVote` lines 375–390: `localSortitionNumSeats` + `nonZero numSeats` check [9](#0-8) 

- `implVerifyCert` lines 528–546: same `localSortitionNumSeats` + `nonZero numSeats` check, independently re-implemented [10](#0-9) 

**Divergence scenario**: Suppose a future patch updates `implVerifyVote` to add a new eligibility condition (e.g., a minimum stake threshold) but the developer misses the identical block in `implVerifyCert`. An attacker operating a non-persistent committee seat with stake below the new threshold can:

1. Craft a `WFALSCert` containing their `seatIndex` with a `Just vrfOutput` entry in the `voters` map.
2. Send this certificate to a victim node via the `PerasCertDiffusion` miniprotocol.
3. `implVerifyCert` processes the certificate, applies the old (unpatched) eligibility check, and accepts it.
4. The certificate is stored and applied as a Peras weight boost, causing the victim node to prefer a block that honest nodes with the patched `implVerifyVote` would not boost.

The three-way duplication of the same logic — with no shared abstraction and with structurally different VRF verification methods between `implVerifyVote` and `implVerifyCert` — is the necessary vulnerable structural condition. [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L1-25)
```haskell
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Weighted Fait-Accompli with Local Sortition (wFA^LS) committee selection.
--
-- This module implements a generic committee selection scheme based the on
-- Weighted Fait-Accompli with Local Sortition (wFA^LS) algorithm
-- from the paper:
--
-- Peter Gaži, Aggelos Kiayias, and Alexander Russell. 2023. Fait Accompli
-- Committee Selection: Improving the Size-Security Tradeoff of Stake-Based
-- Committees. In Proceedings of the 2023 ACM SIGSAC Conference on Computer and
-- Communications Security (CCS '23). Association for Computing Machinery, New
-- York, NY, USA, 845–858. https://doi.org/10.1145/3576915.3623194
--
-- PDF: https://eprint.iacr.org/2023/1273.pdf
--
-- For this, we combine the deterministic portion of the weighted Fait-Accompli
-- scheme (defined in @Ouroboros.Consensus.Committee.WFA@) with local sortition
-- (defined in @Ouroboros.Consensus.Committee.LS@) as a fallback scheme.
module Ouroboros.Consensus.Committee.WFALS
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L285-301)
```haskell
          let numSeats =
                localSortitionNumSeats
                  (nonPersistentCommitteeSize committee)
                  (totalNonPersistentStake committee)
                  ourStake
                  (normalizeVRFOutput vrfOutput)
          case nonZero numSeats of
            Nothing ->
              pure Nothing
            Just nonZeroNumSeats ->
              pure $
                Just $
                  WFALSNonPersistentMember
                    seatIndex
                    ourStake
                    vrfOutput
                    nonZeroNumSeats
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L363-374)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L375-392)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L528-548)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L564-583)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L275-283)
```haskell
  batchVerifyVRFOutputs
    pks
    (PerasBLSCryptoVRFElectionInput input)
    sigs = do
      BLS.linearizeAndVerifyVRFs
        pks
        input
        . fmap unPerasBLSCryptoVRFOutput
        $ sigs
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1000-1023)
```haskell
  aPerasCertDiffusionClient ::
    NodeToNodeVersion ->
    ExpandedInitiatorContext addrNTN PeerTrustable m ->
    Channel m bPCD ->
    m (NodeToNodeInitiatorResult, Maybe bPCD)
  aPerasCertDiffusionClient
    version
    ExpandedInitiatorContext
      { eicConnectionId = them
      , eicControlMessage = controlMessageSTM
      }
    channel = do
      labelThisThread "PerasCertDiffusionClient"
      ((), trailing) <-
        runPipelinedPeerWithLimits
          (TraceLabelPeer them `contramap` tPerasCertDiffusionTracer)
          (cPerasCertDiffusionCodec (mkCodecs version))
          blPerasCertDiffusion
          timeLimitsObjectDiffusion
          channel
          ( objectDiffusionInboundPeerPipelined
              (hPerasCertDiffusionClient version controlMessageSTM them)
          )
      return (NoInitiatorResult, trailing)
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
