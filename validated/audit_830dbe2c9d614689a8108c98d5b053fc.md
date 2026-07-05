### Title
Missing Peras Certificate Validation Allows Adversarial Chain Weight Manipulation via Crafted Certificate - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` function performs **no validation** of inbound Peras certificates received from peers. Any peer can send a crafted `PerasCert` claiming to boost an arbitrary block, and the node will unconditionally accept it, add it to the `PerasCertDB`, and use it to influence chain selection — potentially causing the node to prefer a non-canonical adversarial chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting inbound Peras certificates. The universal instance (used for all block types, including Cardano production blocks) is a stub that always returns `Right` without performing any checks:

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

The `vpcCert` field is set directly to the peer-supplied `cert` — including its `pcCertBoostedBlock` (which block receives the weight boost) and `pcCertRound` — with no cryptographic verification, no committee membership check, no round validity check, and no check that the boosted block actually exists on any known chain.

This function is called directly from the network-facing inbound certificate handler `processCerts` in the object diffusion mini-protocol:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

The `processCerts` function calls `validateCert` on each inbound cert and, if all pass (which they always do), adds them to the database: [4](#0-3) 

The `PerasCertDB.implAddCert` also carries a matching TODO acknowledging the missing validation: [5](#0-4) 

Once a cert is stored, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certs, mapping each `pcCertBoostedBlock` to its `vpcCertBoost`: [6](#0-5) 

This snapshot is consumed directly by chain selection via `preferAnchoredCandidate`, which computes `wsvTotalWeight` as block-count plus weight boost: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork. The cert passes `validatePerasCert` unconditionally. The adversarial block receives a weight boost of `perasWeight params` (the locally configured Peras weight). If this boost is sufficient to make the adversarial chain's `wsvTotalWeight` exceed the honest chain's, `preferAnchoredCandidate` returns `ShouldSwitch` and the node adopts the adversarial chain.

The `SecurityParam` documentation confirms that a single Peras boost can substitute for many blocks of chain length:

> k == 30: we can roll back at most 30 unweighted blocks, or two blocks each having additional weight 14. [8](#0-7) 

This is a **High** impact chain selection bug: an unprivileged peer with a crafted certificate can make an honest node prefer a non-canonical or less-secure chain, violating the Peras security assumption that only legitimately certified blocks receive weight boosts.

---

### Likelihood Explanation

The entry path is the Peras certificate object diffusion mini-protocol, which is a standard peer-to-peer connection. Any connected peer can send a `PerasCert` message. No special privileges, keys, or stake are required. The attack requires only constructing a `PerasCert` CBOR message with an attacker-chosen `pcCertBoostedBlock` and `pcCertRound`, which is trivially possible given the public serialization instances. [9](#0-8) 

---

### Recommendation

The `validatePerasCert` implementation must be replaced with a real validation function that checks, at minimum:

1. **Committee membership**: The certificate must be signed by a quorum of legitimate committee members for the claimed round, verified against the stake distribution from the ledger view.
2. **Round validity**: `pcCertRound` must correspond to a valid, non-expired Peras round relative to the current slot.
3. **Block existence and age**: `pcCertBoostedBlock` must refer to a block that is known, on a valid chain, and satisfies the `PerasBlockMinSlots` minimum age requirement.
4. **Cryptographic signature**: The certificate must carry a valid aggregate/threshold signature from the voting committee.

The `validatePerasCert` signature already accepts `PerasCfg blk` (which contains `PerasParams` including `perasWeight`, `perasRoundLength`, `perasBlockMinSlots`, etc.) and returns `Either (PerasValidationErr blk) (ValidatedPerasCert blk)`, so the interface is already correct — only the implementation is missing. [10](#0-9) 

---

### Proof of Concept

**Setup**: A private testnet running Peras-enabled Cardano nodes with `perasWeight = W` and security parameter `k`.

**Attack**:
1. Attacker mines a fork `F` that is `D` blocks shorter than the honest chain tip (where `D < W`).
2. Attacker connects to a victim node and sends a `PerasCert` message via the object diffusion mini-protocol with:
   - `pcCertRound` = any round number not yet in the victim's cert DB
   - `pcCertBoostedBlock` = the tip of fork `F`
3. `processCerts` calls `validatePerasCert mkPerasParams` on the cert. Since the stub always returns `Right`, the cert is accepted.
4. The cert is stored in `PerasCertDB`. `implGetWeightSnapshot` now returns a snapshot giving fork `F`'s tip a boost of `W`.
5. `addPerasCertAsync` triggers chain selection. `preferAnchoredCandidate` computes:
   - Honest chain total weight: `honest_length + 0 = honest_length`
   - Fork `F` total weight: `(honest_length - D) + W`
   - Since `W > D`, fork `F` is preferred: `ShouldSwitch`.
6. The victim node switches to the adversarial fork `F`. [11](#0-10) [12](#0-11)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-213)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L33-37)
```haskell
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```
