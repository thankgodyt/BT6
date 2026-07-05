### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates, Enabling Unauthorized Chain Weight Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function — the sole gatekeeper before a `PerasCert` is accepted into the `PerasCertDB` and used to boost chain weight in Peras-enabled chain selection — is a stub that unconditionally returns `Right` (success) without performing any cryptographic or semantic validation. This is structurally analogous to M-14: just as M-14 fails to guard against a zero-amount before calling an external market operation, this code fails to guard against an invalid certificate before accepting it into the weight-boosting pipeline. An unprivileged peer can send a crafted `PerasCert` referencing any block on any fork, causing the node to artificially inflate that block's `PerasWeight` and potentially switch to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the function responsible for verifying a `PerasCert` before it is treated as a `ValidatedPerasCert`. The degenerate instance (which is the only instance currently wired into production paths) is:

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

This stub skips all checks: no aggregate BLS signature verification, no quorum stake threshold check, no round-number validity check, and no verification that the boosted block actually exists on a valid chain. Every certificate, regardless of content, is unconditionally promoted to `ValidatedPerasCert`.

This stub is called directly in the inbound certificate processing path:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

The `processCerts` function calls `validateCert` on each inbound certificate and, if all pass (which they always do), adds them to the database: [3](#0-2) 

Once a certificate is in the `PerasCertDB`, `implGetWeightSnapshot` builds a `PerasWeightSnapshot` from all stored certificates, mapping each `pcCertBoostedBlock` to its `vpcCertBoost` weight: [4](#0-3) 

This snapshot is then consumed by `preferAnchoredCandidate` during chain selection. When Peras is enabled (`isEmptyPerasWeightSnapshot` is `False`), chain selection compares fragments by `wsvTotalWeight = BlockNo + weightBoost`: [5](#0-4) 

The `wsvTotalWeight` comparison is the decisive factor: [6](#0-5) 

A second layer of missing validation exists in `implAddCert`, which also carries a TODO acknowledging that non-trivial validation logic is absent: [7](#0-6) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can send a crafted `PerasCert` with `pcCertBoostedBlock` pointing to any block on any fork. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its boost is added to the `PerasWeightSnapshot`. Chain selection then computes `wsvTotalWeight` for candidate fragments using this inflated snapshot. A short adversarial fork whose tip block has been artificially boosted can accumulate a `wsvTotalWeight` exceeding the honest chain's weight, causing the node to switch to the non-canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Peras.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a public network-facing endpoint. Any peer that can establish a connection can send a `PerasCert` message. The crafted certificate requires only a valid CBOR encoding of a `PerasCert` (round number + block point) — no cryptographic material is needed because `validatePerasCert` never checks signatures. On a private testnet or any deployment with Peras enabled, this is trivially exploitable by any connected peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that performs, at minimum:
1. Aggregate BLS signature verification over the election identifier and boosted block hash.
2. Quorum stake threshold check: the sum of voter stakes must meet `perasQuorumStakeThreshold`.
3. Round-number validity: the round must be within the expected window relative to the current chain tip.
4. Voter eligibility: each voter seat index must correspond to a registered committee member with non-zero stake.

The concrete `EveryoneVotes` committee already implements `implVerifyCert` with these checks: [8](#0-7) 

This logic should be wired into the `BlockSupportsPeras` instance's `validatePerasCert` rather than the current unconditional `Right` stub.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to an honest node via the ObjectDiffusion mini-protocol for Peras certificates.
2. Construct a `PerasCert` with:
   - `pcCertRound`: any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock`: the `BlockPoint` of a block on an adversarial fork that is shorter than the honest chain
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams`, which returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB`. `implGetWeightSnapshot` now includes a boost of `perasWeight params` for the adversarial block.
5. `chainSelSync` processes the certificate. `preferAnchoredCandidate` computes `wsvTotalWeight` for the adversarial fragment: `BlockNo(adversarial_tip) + boost`. If `boost` is large enough to exceed `BlockNo(honest_tip)`, `ShouldSwitch` is returned and the node rolls back to the adversarial chain.

The `perasWeight` value used in the stub is taken from `mkPerasParams` (a hardcoded placeholder), but an attacker controlling the certificate content can send multiple certificates for different blocks on the same fork, accumulating weight additively via `addToPerasWeightSnapshot`: [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```
