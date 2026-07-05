### Title
Peras Certificate Voter Bitmap Assigns Persistent/Non-Persistent Eligibility by Seat-Index Position Rather Than Committee Configuration, Enabling VRF Proof Bypass — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs`)

---

### Summary

The `fromCompactRepr` function in `Cert/V1.hs` decodes the `PerasCertVoters` bitmap by assigning persistent vs. non-persistent voter status based solely on the **ordinal position** of each set bit in the ascending-sorted list of seat indices, not on the actual committee configuration. A crafted certificate received from an unprivileged peer can therefore cause non-persistent voters (who must supply a VRF eligibility proof) to be decoded as persistent voters (no proof required), bypassing VRF eligibility verification. The `implAddCert` function in `PerasCertDB/Impl.hs` carries an explicit TODO acknowledging that non-trivial validation logic has not yet been implemented, leaving the decoded certificate accepted into the weight-snapshot store without cryptographic cross-check.

---

### Finding Description

**Encoding convention (`CompactPerasCertVoters`):**

The wire format for a Peras certificate's voter set stores two fields:
1. `votersBitmap` — a `Bitmap Word16` whose set bits identify the seat indices of all voters.
2. `nonPersistentSigs` — a `[VRFOutput]` list whose length equals the number of non-persistent voters.

The documented convention is: *"the last `np` indices in the bitmap that are flipped to 1 correspond to non-persistent voters"*.

**Root cause in `fromCompactRepr`:**

```haskell
let voterSeatIndices = PerasSeatIndex <$> Bitmap.toIndices votersBitmap
-- toIndices returns indices in ascending order
let numPersistentVoters = length voterSeatIndices - length nonPersistentSigs
let persistentProofs   = take numPersistentVoters (repeat PersistentPerasVoteEligibilityProof)
let nonPersistentProofs = fmap NonPersistentPerasVoteEligibilityProof nonPersistentSigs
let voters = NEMap.fromAscList . NonEmpty.fromList
               . zip voterSeatIndices
               $ persistentProofs <> nonPersistentProofs
``` [1](#0-0) 

The first `numPersistentVoters` seat indices (lowest-numbered) receive `PersistentPerasVoteEligibilityProof`; the last `np` seat indices (highest-numbered) receive `NonPersistentPerasVoteEligibilityProof`. **No cross-check against the actual committee is performed.** The only guards are:

- voters bitmap must be non-empty,
- `length nonPersistentSigs ≤ length voterSeatIndices`. [2](#0-1) 

**Missing validation in `implAddCert`:**

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert :: ...
``` [3](#0-2) 

The function currently inserts any structurally well-formed `ValidatedPerasCert` into `pcdsCertsByTicket` and immediately exposes it through `getWeightSnapshot`, which drives Peras chain selection. [4](#0-3) 

**Analogy to the reported vulnerability:**

| MultiMerkleDistributor | Ouroboros Consensus |
|---|---|
| Bitmap bit at index `i` is claimed by whichever user the *current* Merkle tree places at index `i` | Bitmap bit at seat index `s` is decoded as persistent/non-persistent based on its *ordinal rank* among all set bits, not on the committee's actual classification of seat `s` |
| Updating the Merkle root without resetting the bitmap causes index→user mismatches | A crafted certificate can place a non-persistent voter's seat at a low index so it is decoded as persistent, or a persistent voter's seat at a high index so it is decoded as non-persistent |
| Result: double-claim or claim bypass | Result: VRF eligibility proof bypass or spurious proof rejection |

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote eligibility checks.**

A peer that can send a certificate over the network (via the object-diffusion mini-protocol) can craft a `PerasCert` whose `votersBitmap` places non-persistent committee members at low seat indices. `fromCompactRepr` will decode those seats as persistent, requiring no VRF output. The certificate passes structural deserialization, is inserted into `PerasCertDB`, and its boosted-block weight is immediately reflected in `getWeightSnapshot`. This weight is consumed by `switchTo` in `ChainSel.hs` during chain selection, meaning the attacker can artificially boost an arbitrary block's chain weight without possessing valid VRF eligibility proofs for the non-persistent committee members. [5](#0-4) 

---

### Likelihood Explanation

**Likelihood: Medium.**

The Peras object-diffusion layer is designed to accept certificates from any connected peer. The `fromCBOR` instance for `PerasCertVoters` calls `fromCompactRepr` automatically on receipt. The only structural check that would reject a crafted certificate is the `length nonPersistentSigs ≤ length voterSeatIndices` guard. A committee with interleaved persistent and non-persistent seat indices (which is the expected real-world configuration) is sufficient to trigger the mismatch. The TODO in `implAddCert` confirms that cryptographic cross-validation against the committee is not yet in place.

---

### Recommendation

1. **`fromCompactRepr` must not infer voter type from ordinal position.** The compact encoding should either (a) store an explicit per-voter type bit alongside each seat index, or (b) require the caller to supply the committee configuration so that each decoded seat index can be looked up to determine its true persistent/non-persistent status before constructing `PerasCertVoters`.

2. **`implAddCert` must validate the certificate before insertion.** The referenced issue (`cardano-peras/issues/120`) should be resolved before the Peras diffusion path is enabled on any network that enforces certificate-based chain selection. At minimum, for each voter in the decoded `PerasCertVoters`, the implementation must verify that the eligibility proof type matches the committee's classification of that seat index, and that any `NonPersistentPerasVoteEligibilityProof` VRF output is cryptographically valid for the claimed seat.

---

### Proof of Concept

Assume a committee where:
- Seat 1 is **non-persistent** (requires a VRF output)
- Seat 5 is **persistent** (no VRF output required)

**Attacker constructs:**
```
votersBitmap    = {1, 5}   (bits 1 and 5 set)
nonPersistentSigs = [fake_vrf]   (length = 1)
```

**`fromCompactRepr` decodes:**
```
voterSeatIndices      = [1, 5]
numPersistentVoters   = 2 - 1 = 1
→ seat 1 → PersistentPerasVoteEligibilityProof   (no VRF proof checked)
→ seat 5 → NonPersistentPerasVoteEligibilityProof fake_vrf
```

Seat 1 (a non-persistent voter) is accepted without any VRF proof. The certificate passes `fromCBOR`, is inserted by `implAddCert` into `PerasCertDB`, and its boosted-block weight is applied to chain selection via `getWeightSnapshot`, allowing the attacker to artificially elevate a chosen block's Peras weight without holding valid committee credentials. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L120-148)
```haskell
-- | Compact representation of the voters in a Peras certificate.
--
-- This compact representation consists of a bitmap of voter seat indices and a
-- list of non-persistent eligibility proofs (VRF outputs). In this setup, the
-- last @np@ indices in the bitmap that are flipped to 1 correspond to
-- non-persistent voters, where @np@ is the length of the list of non-persistent
-- eligibility proofs. The remaining flipped indices in the bitmap correspond
-- to persistent voters.
--
-- @
--   fromCompactRepr
--      CompactPerasCertVoters {
--        votersBitmap = <01101011>,
--        nonPersistentSigs = [np1, np2, np3]
--      }
--   ==
--   PerasCertVoters {
--     1 => persistent
--     2 => persistent
--     4 => non-persistent(np1)
--     6 => non-persistent(np2)
--     7 => non-persistent(np3)
--   }
-- @
data CompactPerasCertVoters
  = CompactPerasCertVoters
  { votersBitmap :: !(Bitmap Word16)
  , nonPersistentSigs :: ![VRFOutput PerasBLSCrypto]
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L165-178)
```haskell
    when (null voterSeatIndices) $
      throwError "Invalid Peras certificate: empty voters bitmap"

    when (length nonPersistentSigs > length voterSeatIndices) $
      throwError $
        unlines
          [ "Invalid Peras certificate:"
              <> " more non-persistent voter eligibility proofs were provided"
              <> " than the number of voters in the certificate"
          , " * number of voters: "
              <> show (length voterSeatIndices)
          , " * number of proofs: "
              <> show (length nonPersistentSigs)
          ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L180-192)
```haskell
    let numPersistentVoters =
          length voterSeatIndices - length nonPersistentSigs
    let persistentProofs =
          take numPersistentVoters (repeat PersistentPerasVoteEligibilityProof)
    let nonPersistentProofs =
          fmap NonPersistentPerasVoteEligibilityProof nonPersistentSigs
    let voters =
          NEMap.fromAscList
            . NonEmpty.fromList
            . zip voterSeatIndices
            $ persistentProofs <> nonPersistentProofs

    pure (PerasCertVoters voters)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L880-904)
```haskell
switchTo ::
  forall m blk.
  ( IOLike m
  , LedgerSupportsProtocol blk
  , InspectLedger blk
  , HasHardForkHistory blk
  , HasCallStack
  ) =>
  ChainDbEnv m blk ->
  PerasWeightSnapshot blk ->
  -- | Which block we performed chain selection for (if any). This is 'Nothing'
  -- when reprocessing blocks that were postponed due to the Limit on Eagerness
  -- (cf 'ChainSelReprocessLoEBlocks').
  Maybe (RealPoint blk) ->
  -- | Chain diff to switch to
  ChainDiff (Header blk) ->
  ReasonForSwitch' blk ->
  -- | Forker at the tip of the above ChainDiff
  SuccessForkerAction m ExtLedgerState blk
switchTo CDB{..} weights triggerPt chainDiff reason = MkSuccessForkerAction $ \forker -> do
  traceWith addBlockTracer $
    ChangingSelection $
      castPoint $
        Diff.getTip chainDiff
  (curChain, newChain, events, prevTentativeHeader, newLedger, closeOrphanedStates) <- atomically $ do
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Bitmap.hs (L36-46)
```haskell
-- | A compact bitmap representation over an index type.
--
-- NOTE: the logical upper bound is stored explicitly so serialisation
-- round-trips exactly.
data Bitmap a
  = Bitmap
      -- | Logical upper bound
      !a
      -- | Payload
      !ByteString
  deriving Eq
```
