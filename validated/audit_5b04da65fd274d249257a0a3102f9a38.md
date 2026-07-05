### Title
Incorrect Compact Encoding of Interleaved Persistent/Non-Persistent Voters in Peras Certificate Serialization - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs`)

---

### Summary

`fromCompactRepr` in `Ouroboros.Consensus.Peras.Cert.V1` incorrectly reconstructs voter eligibility proofs from the compact `CompactPerasCertVoters` wire format. The encoding scheme silently assumes all persistent voters occupy lower seat indices than all non-persistent voters, but this invariant is never enforced. When a legitimately-forged WFALS certificate contains interleaved persistent and non-persistent voters (which is the normal case), the round-trip `ToCBOR` → `FromCBOR` assigns VRF outputs to the wrong seat indices. Every receiving node then fails certificate verification, permanently suppressing the Peras chain boost for that round.

---

### Finding Description

`PerasCertVoters` is serialized in a compact two-field form:

```
CompactPerasCertVoters {
  votersBitmap    :: Bitmap Word16   -- all voter seat indices
  nonPersistentSigs :: [VRFOutput]   -- VRF outputs, in ascending seat-index order
}
```

The documented invariant (comment at line 123–127) is:

> "the **last** `np` indices in the bitmap that are flipped to 1 correspond to non-persistent voters … The **remaining** flipped indices … correspond to persistent voters."

`toCompactRepr` collects `nonPersistentSigs` by iterating voters in ascending seat-index order and keeping only non-persistent proofs:

```haskell
nonPersistentSigs =
  catMaybes (fmap getNonPersistentSig votersByAscSeatIndex)
``` [1](#0-0) 

`fromCompactRepr` then reconstructs voters by assigning the first `n − np` set bits as persistent and the last `np` set bits as non-persistent:

```haskell
let numPersistentVoters = length voterSeatIndices - length nonPersistentSigs
let persistentProofs    = take numPersistentVoters (repeat PersistentPerasVoteEligibilityProof)
let nonPersistentProofs = fmap NonPersistentPerasVoteEligibilityProof nonPersistentSigs
let voters = NEMap.fromAscList . NonEmpty.fromList
               . zip voterSeatIndices
               $ persistentProofs <> nonPersistentProofs
``` [2](#0-1) 

**The flaw:** the compact format records *how many* non-persistent proofs there are, but not *which* seat indices they belong to. Decoding always assigns the first `n − np` seats as persistent and the last `np` seats as non-persistent, regardless of the actual interleaving.

**Concrete counter-example:**

Original certificate voters (produced by WFALS `implForgeCert`):

| Seat | Type |
|------|------|
| 2 | NonPersistent(np1) |
| 5 | Persistent |
| 7 | NonPersistent(np2) |

`toCompactRepr` emits: `votersBitmap = {2,5,7}`, `nonPersistentSigs = [np1, np2]`.

`fromCompactRepr` reconstructs:

| Seat | Decoded Type |
|------|------|
| 2 | **Persistent** ← wrong |
| 5 | **NonPersistent(np1)** ← wrong |
| 7 | NonPersistent(np2) |

VRF output `np1` is now attributed to seat 5 (a persistent member) instead of seat 2, and seat 2 is incorrectly treated as persistent.

The WFALS committee produces exactly this interleaving whenever a non-persistent voter holds a lower seat index than any persistent voter, which is a normal outcome of the sortition algorithm:

```haskell
votesInAscendingSeatIndexOrder =
  flip NonEmpty.sortWith (getRawVotes votes) $ \case
    WFALSPersistentVote    seatIndex _ _ _   -> seatIndex
    WFALSNonPersistentVote seatIndex _ _ _ _ -> seatIndex
``` [3](#0-2) 

---

### Impact Explanation

After deserialization, `implVerifyCert` (WFALS) iterates voters in ascending seat-index order and pattern-matches on `(seatIndex, Nothing)` for persistent and `(seatIndex, Just vrfOutput)` for non-persistent:

```haskell
(seatIndex, Nothing)
  | ... , isPersistentMember seatIndex committee -> ...
  | otherwise -> Left (NotAPersistentMember seatIndex)
(seatIndex, Just vrfOutput)
  | ... , not (isPersistentMember seatIndex committee) -> ...
  | otherwise -> Left (NotANonPersistentMember seatIndex)
``` [4](#0-3) 

With the corrupted voter map, a seat that is actually non-persistent in the committee is presented as persistent (`Nothing`), triggering `NotAPersistentMember`, and a seat that is actually persistent is presented as non-persistent (`Just vrfOutput`), triggering `NotANonPersistentMember`. Certificate verification fails deterministically on every receiving node.

`processCerts` rejects the entire batch and disconnects from the sending peer:

```haskell
(errors, _) -> throw (PerasCertInboundException errors)
``` [5](#0-4) 

The Peras chain boost for the affected round is never applied. Because the boost is the mechanism by which Peras strengthens chain selection security, suppressing it degrades chain selection to the baseline Praos security level for that round, which is the exact security weakening Peras is designed to prevent.

**Impact class:** High — Peras certificate verification bypass that prevents the chain boost from being applied, weakening chain selection security beyond the intended Peras security assumptions.

---

### Likelihood Explanation

The WFALS committee assigns seat indices by sorting all eligible voters (persistent and non-persistent) together by seat index. Persistent members occupy the lowest-numbered seats in the WFA portion of the scheme, while non-persistent members are assigned seats via local sortition starting from `persistentCommitteeSize`. In a typical committee with both persistent and non-persistent members, the seat ranges do not overlap, so interleaving does not occur in the current WFA+LS split. However:

1. The code places **no enforcement** of the "all persistent seats < all non-persistent seats" invariant anywhere in `toCompactRepr`, `fromCompactRepr`, or the `PerasCertVoters` type.
2. Any future change to seat assignment, or any committee configuration where the ranges overlap, immediately triggers the bug.
3. The `PerasCertVoters` type is a plain `Map PerasSeatIndex PerasVoteEligibilityProof` with no ordering constraint, so any code path that constructs it directly (e.g., tests, future committee schemes) can produce interleaved voters.
4. The `genPerasCert True` generator used in tests explicitly generates interleaved voters, meaning the bug is exercised in the test suite but the serialization round-trip is not tested end-to-end for the WFALS case with interleaved voters. [6](#0-5) 

---

### Recommendation

Replace the positional encoding with an explicit per-voter type tag. The simplest fix is to store, alongside the bitmap, a second bitmap (or a list of seat indices) identifying which set bits are non-persistent, rather than relying on positional ordering:

```haskell
data CompactPerasCertVoters = CompactPerasCertVoters
  { votersBitmap           :: !(Bitmap Word16)
  , nonPersistentVotersBitmap :: !(Bitmap Word16)  -- subset of votersBitmap
  , nonPersistentSigs      :: ![VRFOutput PerasBLSCrypto]
  }
```

`fromCompactRepr` then uses `nonPersistentVotersBitmap` to determine which seat indices receive non-persistent proofs, eliminating the positional assumption entirely. Alternatively, add a hard assertion in `toCompactRepr` that all persistent seat indices are strictly less than all non-persistent seat indices, and document this as a required invariant of the WFALS seat assignment.

---

### Proof of Concept

Given the existing `genPerasCert True` generator (which produces interleaved voters), the following property fails:

```haskell
prop_roundtrip_compact :: V1.PerasCertVoters -> Bool
prop_roundtrip_compact voters =
  case V1.fromCompactRepr (V1.toCompactRepr voters) of
    Left _         -> False
    Right voters'  -> voters == voters'
```

Specifically, for `voters = {2 → NonPersistent(np1), 5 → Persistent, 7 → NonPersistent(np2)}`:

- `toCompactRepr` → `{bitmap={2,5,7}, nonPersistentSigs=[np1,np2]}`
- `fromCompactRepr` → `{2 → Persistent, 5 → NonPersistent(np1), 7 → NonPersistent(np2)}`
- `voters ≠ voters'` — the round-trip is not an identity.

The corrupted certificate then fails `implVerifyCert` with `NotAPersistentMember 2` (seat 2 is non-persistent in the committee but decoded as persistent) and `NotANonPersistentMember 5` (seat 5 is persistent in the committee but decoded as non-persistent with a VRF output). [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L154-192)
```haskell
fromCompactRepr ::
  CompactPerasCertVoters ->
  Either String PerasCertVoters
fromCompactRepr
  CompactPerasCertVoters
    { votersBitmap
    , nonPersistentSigs
    } = do
    let voterSeatIndices =
          PerasSeatIndex <$> Bitmap.toIndices votersBitmap

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L197-218)
```haskell
toCompactRepr ::
  PerasCertVoters ->
  CompactPerasCertVoters
toCompactRepr (PerasCertVoters voters) =
  CompactPerasCertVoters
    { votersBitmap
    , nonPersistentSigs
    }
 where
  logicalUpperBound =
    unPerasSeatIndex (fst (NEMap.findMax voters))
  votersByAscSeatIndex =
    NonEmpty.toList (NEMap.toAscList voters)
  votersSeatIndices =
    fmap (unPerasSeatIndex . fst) votersByAscSeatIndex
  votersBitmap =
    Bitmap.fromIndices logicalUpperBound votersSeatIndices
  nonPersistentSigs =
    catMaybes (fmap getNonPersistentSig votersByAscSeatIndex)
  getNonPersistentSig = \case
    (_, PersistentPerasVoteEligibilityProof) -> Nothing
    (_, NonPersistentPerasVoteEligibilityProof p) -> Just p
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L478-481)
```haskell
  votesInAscendingSeatIndexOrder =
    flip NonEmpty.sortWith (getRawVotes votes) $ \case
      WFALSPersistentVote seatIndex _ _ _ -> seatIndex
      WFALSNonPersistentVote seatIndex _ _ _ _ -> seatIndex
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L502-523)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Util.hs (L151-188)
```haskell
        choose @Word16 (0, fromIntegral size * 10)
  numPersistentVoters <-
    case shouldGenNonPersistent of
      True -> choose (0, numVoters)
      False -> pure numVoters
  persistentVoters <-
    if numPersistentVoters == 0
      then pure []
      else forM [0 .. numPersistentVoters - 1] $ \i -> do
        let proof = V1.PersistentPerasVoteEligibilityProof
        pure (PerasSeatIndex i, proof)
  nonPersistentVoters <-
    if numPersistentVoters == numVoters
      then pure []
      else forM [numPersistentVoters .. numVoters - 1] $ \i -> do
        proof <-
          V1.NonPersistentPerasVoteEligibilityProof
            . PerasBLSCryptoVRFOutput
            <$> genSignature (Proxy @BLS.VRF)
        pure (PerasSeatIndex i, proof)
  voters <-
    fmap (snd . fmap catMaybes)
      . mapAccumM
        ( \canDrop (i, proof) -> do
            voter <-
              frequency
                [ (75, pure (Just (i, proof)))
                , (if canDrop then 25 else 0, pure Nothing)
                ]
            pure
              ( canDrop || voter == Nothing
              , voter
              )
        )
        False
      $ persistentVoters <> nonPersistentVoters
  pure $
    V1.PerasCertVoters (NEMap.fromList (NonEmpty.fromList voters))
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Bitmap.hs (L66-83)
```haskell
fromIndices :: Integral a => a -> [a] -> Bitmap a
fromIndices maxIx flipped =
  Bitmap maxIx $
    ByteString.unsafeCreate nBytes $ \ptr -> do
      fillBytes ptr 0 nBytes
      forM_ flipped $ \ix -> do
        let !i = fromIntegral ix :: Int
        when (i >= 0 && i <= maxI) $ do
          let !byteIx = i `quot` 8
          let !bitIx = i `rem` 8
          let !mask = bitMask bitIx
          w <- peekByteOff ptr byteIx :: IO Word8
          pokeByteOff ptr byteIx (w .|. mask)
 where
  !maxI = fromIntegral maxIx :: Int
  !nBytes = (maxI `quot` 8) + 1

  bitMask k = fromIntegral ((1 :: Int) `unsafeShiftL` k)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Bitmap.hs (L87-107)
```haskell
toIndices :: Integral a => Bitmap a -> [a]
toIndices (Bitmap maxIx bitmap) =
  goBytes 0
 where
  !maxI = fromIntegral maxIx :: Int
  !nBytes = ByteString.length bitmap

  goBytes !byteIx
    | byteIx >= nBytes = []
    | otherwise =
        let !w = ByteString.index bitmap byteIx
         in goBits (byteIx * 8) w <> goBytes (byteIx + 1)

  goBits !_ 0 = []
  goBits !base !w =
    let !bitIx = countTrailingZeros w
        !i = base + bitIx
        !w' = w .&. (w - 1)
     in if i <= maxI
          then fromIntegral i : goBits base w'
          else []
```
