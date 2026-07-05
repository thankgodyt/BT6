### Title
VRF Eligibility Proof Verification Result Silently Discarded in Non-Persistent Vote Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs`)

---

### Summary

In `implVerifyVote` for `WFALSNonPersistentVote`, the call to `evalVRF` (which verifies the voter's VRF proof of eligibility) is wrapped with `void $`, causing its `Either String (VRFOutput crypto)` return value to be unconditionally discarded. This is the direct analog of the ERC20 unchecked-return-value bug: a cryptographic verification function returns a failure indicator (`Left`), but the caller silently ignores it and proceeds as if verification succeeded. As a result, any non-persistent committee candidate can submit a vote with a completely invalid VRF eligibility proof and have it accepted.

---

### Finding Description

`evalVRF` is the class method defined in `CryptoSupportsVRF` with the signature:

```haskell
evalVRF ::
  VRFPoolContext crypto ->
  VRFElectionInput crypto ->
  Either String (VRFOutput crypto)
``` [1](#0-0) 

When called with a `VRFVerifyContext`, it verifies that the supplied `VRFOutput` is a valid BLS signature over the election input under the voter's VRF verification key. In the concrete `PerasBLSCrypto` instance, `VRFVerifyContext pk sig` calls `BLS.verifyWithRole @VRF` and returns `Left` on failure: [2](#0-1) 

In `implVerifyVote`, the `WFALSNonPersistentVote` branch constructs a `VRFVerifyContext` and calls `evalVRF`, but wraps the entire call in `void $`:

```haskell
void $ bimap InvalidVoterEligibilityProof id $ do
  evalVRF
    vrfContext
    ( mkVRFElectionInput
        @crypto
        (epochNonce committee)
        electionId
    )
``` [3](#0-2) 

`bimap InvalidVoterEligibilityProof id` correctly maps a `Left` failure to the `InvalidVoterEligibilityProof` error constructor, but `void $` then throws away the entire `Either` — both the `Left` failure and the `Right` success — before the monadic bind in the surrounding `do`-block can propagate the error. The function then unconditionally falls through to compute `numSeats` and return `Right (WFALSNonPersistentMember ...)`.

**Contrast with correct usage elsewhere:**

- In `implCheckShouldVote`, `evalVRF` is called correctly — its result is bound and used:
  ```haskell
  vrfOutput <- bimap CryptoError id $ do evalVRF vrfContext ...
  ``` [4](#0-3) 

- In `implVerifyCert`, `batchVerifyVRFOutputs` is called and its result is checked via `bimap InvalidCertSignature id $`: [5](#0-4) 

Only `implVerifyVote` for non-persistent votes silently discards the VRF verification result.

---

### Impact Explanation

**Severity: Critical** — Bypass of VRF eligibility verification enabling unauthorized vote acceptance.

The VRF proof is the sole mechanism by which non-persistent committee members prove their eligibility to participate in a given election under the WFALS scheme. Non-persistent members are selected per-election via local sortition: only those whose VRF output over the election input falls below a threshold (computed by `localSortitionNumSeats`) are eligible. By discarding the VRF verification result, `implVerifyVote` accepts any `WFALSNonPersistentVote` from any non-persistent candidate regardless of whether their VRF output is cryptographically valid for the claimed election. An attacker can:

1. Submit votes with a fabricated or recycled VRF output from a different election.
2. Submit votes with a VRF output computed under a different key.
3. Submit votes with a zero-byte or otherwise invalid VRF output.

All of these will pass `implVerifyVote` and be counted toward the election result, enabling unauthorized vote acceptance and potential certificate forgery for elections the attacker was not legitimately selected for.

---

### Likelihood Explanation

Any pool operator that is a non-persistent committee candidate (i.e., not in the top-`k` persistent seats) can exploit this. No special privilege is required beyond being a known candidate in the stake distribution. The attacker only needs to craft a `WFALSNonPersistentVote` with an arbitrary `VRFOutput` field and a valid vote signature (which they can produce legitimately with their own key). The invalid VRF output will not be caught by `implVerifyVote`.

---

### Recommendation

Remove `void $` and bind the result of `evalVRF` so that a `Left` failure propagates through the surrounding `Either` monad, matching the pattern used in `implCheckShouldVote`:

```haskell
-- Before (broken):
void $ bimap InvalidVoterEligibilityProof id $ do
  evalVRF vrfContext (mkVRFElectionInput @crypto (epochNonce committee) electionId)

-- After (correct):
_ <- bimap InvalidVoterEligibilityProof id $ do
  evalVRF vrfContext (mkVRFElectionInput @crypto (epochNonce committee) electionId)
```

Or equivalently, bind the output (which is not used downstream since `vrfOutput` is already in scope from the vote constructor):

```haskell
bimap InvalidVoterEligibilityProof (const ()) $
  evalVRF vrfContext (mkVRFElectionInput @crypto (epochNonce committee) electionId)
```

---

### Proof of Concept

Given a `WFALSVotingCommittee` with at least one non-persistent candidate pool `P`:

1. Pool `P` constructs a `WFALSNonPersistentVote` for election `E` with:
   - A valid `seatIndex` for `P` in the non-persistent range.
   - A valid vote signature over `(electionId, candidate)` using `P`'s vote signing key.
   - An **invalid** `vrfOutput` — e.g., the VRF output from a completely different election, or a random byte string.

2. Call `verifyVote committee vote`.

3. In `implVerifyVote`, the `WFALSNonPersistentVote` branch:
   - Passes the seat-bounds check (line 352–353).
   - Passes the vote signature check (lines 357–362).
   - Calls `evalVRF (VRFVerifyContext voterVRFVerificationKey invalidVrfOutput) input` → returns `Left "BLS verification failed"`.
   - `bimap InvalidVoterEligibilityProof id (Left "...")` → `Left (InvalidVoterEligibilityProof "...")`.
   - `void $ Left (InvalidVoterEligibilityProof "...")` → `()` — **error discarded**.
   - Computes `numSeats` using the invalid `vrfOutput` (which may or may not yield zero seats, but the VRF proof itself is never enforced).
   - Returns `Right (WFALSNonPersistentMember seatIndex voterStake invalidVrfOutput nonZeroNumSeats)`.

4. The vote is accepted as valid despite the VRF proof being cryptographically invalid. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto.hs (L141-144)
```haskell
  evalVRF ::
    VRFPoolContext crypto ->
    VRFElectionInput crypto ->
    Either String (VRFOutput crypto)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L201-208)
```haskell
  evalVRF context (PerasBLSCryptoVRFElectionInput input) =
    case context of
      VRFSignContext sk -> do
        let sig = BLS.signWithRole @VRF (BLS.coercePrivateKey @VRF sk) input
        pure $ PerasBLSCryptoVRFOutput sig
      VRFVerifyContext pk (PerasBLSCryptoVRFOutput sig) -> do
        BLS.verifyWithRole @VRF (BLS.coercePublicKey @VRF pk) input sig
        pure $ PerasBLSCryptoVRFOutput sig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L277-284)
```haskell
            bimap CryptoError id $ do
              evalVRF
                vrfContext
                ( mkVRFElectionInput
                    @crypto
                    (epochNonce committee)
                    electionId
                )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L351-390)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L575-583)
```haskell
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
