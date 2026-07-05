### Title
Unconditional Peras Certificate Acceptance Bypasses Quorum Verification, Enabling Arbitrary Chain-Weight Injection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound `PerasCert` without performing any cryptographic or quorum verification. This is wired directly into the live certificate diffusion pipeline. Any unprivileged peer can inject a crafted certificate for an arbitrary block, causing the receiving node to apply a Peras weight boost to that block and prefer an attacker-chosen fork over the canonical chain.

---

### Finding Description

**Vulnerability class:** Bypass of certificate/vote verification that enables unauthorized certificate acceptance and chain-selection manipulation — the direct analog of the Pyth "voter weight manipulation" class, where the intended threshold check is circumvented so that a party with insufficient stake can cause a governance outcome (here: a chain-weight boost) to be accepted.

**Root cause — `validatePerasCert` always returns `Right`:**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for certificate acceptance. The sole production instance (for all `StandardHash blk`) is:

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

No signature is checked, no quorum is verified, no round bounds are enforced. Every certificate is stamped `ValidatedPerasCert` with the full `perasWeight` boost.

**Attacker-controlled entry path — production certificate diffusion pipeline:**

`makePerasCertPoolWriterFromChainDB` (the production writer used when the ChainDB is the backing store) passes this stub directly as the validator:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` iterates every certificate received from a remote peer, calls the validator, and — because validation always succeeds — stores every certificate and triggers async chain-selection side-effects: [3](#0-2) 

**How the accepted certificate affects chain selection:**

A stored `ValidatedPerasCert` is converted into a `PerasWeightSnapshot` entry via `addToPerasWeightSnapshot`. `weightBoostOfFragment` then sums all boosts for blocks on a fragment: [4](#0-3) 

`WeightedSelectView` uses `wsvTotalWeight = blockNo + weightBoost` as the primary chain-selection key: [5](#0-4) 

A forged certificate with `perasWeight = 15` (the default) adds 15 units of weight to the attacker's chosen block, making a fork 15 blocks shorter than the canonical chain appear heavier.

**Parallel: `stakeAboveThreshold` unit mismatch compounds the risk**

Even in the path where votes are aggregated locally (rather than certificates injected directly), `stakeAboveThreshold` compares accumulated `PerasVoteStake` against the quorum threshold without enforcing normalization:

```haskell
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. ...
-- this function only makes sense when both values are relative (normalized)
-- values, so we should either normalize the 'PerasVoteStake' before calling
-- this function, or change this function to accept a stake distribution and
-- perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
``` [6](#0-5) 

If `PerasVoteStake` values are stored as absolute ledger stake (e.g., a voter with 80% of total stake stores `0.8`) and the threshold is `3/4 = 0.75`, quorum is reached by a single voter — directly mirroring the Pyth pattern where the denominator (total supply) is manipulated to lower the effective threshold.

---

### Impact Explanation

An unprivileged peer can inject a `PerasCert` for any block on any fork. The receiving node will:
1. Accept the certificate unconditionally.
2. Apply a `PerasWeight 15` boost to the attacker-chosen block.
3. Prefer any chain containing that block if it is within 15 blocks of the canonical tip.

This is a **consensus safety failure**: honest nodes can be made to prefer a non-canonical, less-secure chain purely through a crafted network message, with no stake, keys, or privileged access required.

---

### Likelihood Explanation

The attack requires only a TCP connection to a node running the Peras certificate object-diffusion mini-protocol. The attacker needs to know a valid block hash to target (publicly observable from the chain). No cryptographic material, stake, or operator access is needed. The CBOR serialization format for `PerasCert` is defined and public. [7](#0-6) 

---

### Recommendation

Before deploying Peras to production, `validatePerasCert` must perform at minimum:
1. **Aggregate BLS signature verification** over the election ID and boosted block hash against the claimed voters' public keys.
2. **Quorum check**: verify that the signers' combined stake meets `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
3. **Round bounds check**: verify the certificate round is within the valid window.

For `stakeAboveThreshold`, enforce that `PerasVoteStake` values are always normalized (divided by total committee stake) before comparison, or pass the total stake into the function and normalize internally — analogous to the Pyth remediation of replacing the manipulable mint supply with a fixed constant denominator.

---

### Proof of Concept

1. Attacker connects to a node via the Peras certificate diffusion mini-protocol.
2. Attacker observes block hash `H` on a minority fork at slot `S`.
3. Attacker serializes `PerasCert { pcCertRound = R, pcCertBoostedBlock = H }` as CBOR and sends it.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = PerasWeight 15 })`.
5. `ChainDB.addPerasCertAsync` stores the certificate; `addToPerasWeightSnapshot` records `+15` weight for block `H`.
6. `weightedSelectView` now computes `wsvTotalWeight` for any fragment containing `H` as `blockNo + 15`.
7. A fork containing `H` that is up to 15 blocks shorter than the canonical chain is now preferred by chain selection, causing the node to roll back to the attacker's fork. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-173)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
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
