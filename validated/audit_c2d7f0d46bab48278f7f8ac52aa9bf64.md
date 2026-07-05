### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or structural checks. An unprivileged peer can send a crafted `PerasCert` pointing to any block, which will be accepted, stored, and used to inflate the Peras weight of an adversarial chain fragment, causing the honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate's authenticity before it can influence chain selection. The degenerate instance that covers all block types (the only instance currently in the codebase) implements this gate as a no-op:

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

No committee membership check, no BLS/VRF signature verification, no round-number bounds check, and no check that the boosted block actually exists on any known chain are performed. Every certificate is unconditionally wrapped in `ValidatedPerasCert` and assigned the full `perasWeight`.

This stub is wired directly into the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this function on every new certificate received from a peer, and if it returns `Right`, the certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` enqueues the certificate for `chainSelSync`, which stores it in the `PerasCertDB` and then re-runs chain selection using the updated `PerasWeightSnapshot`: [4](#0-3) 

Chain selection compares candidate fragments using `preferAnchoredCandidate`, which sums block count and Peras weight boost. A certificate that boosts a block on an adversarial fork adds `perasWeight` to that fork's `wsvWeightBoost`, potentially making it heavier than the honest chain: [5](#0-4) 

The `PerasWeightSnapshot` used in `weightedSelectView` is populated directly from the `PerasCertDB` contents, so any accepted certificate immediately affects the comparison: [6](#0-5) 

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Send a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork and `pcCertRound` set to any round number not yet in the `PerasCertDB`.
2. `validatePerasCert` accepts it unconditionally.
3. The certificate is stored and its weight boost is applied to the adversarial fork's `PerasWeightSnapshot`.
4. `preferAnchoredCandidate` now sees the adversarial fork as heavier than the honest chain.
5. The node switches to the adversarial chain, accepting an invalid or non-canonical ledger state.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of Ouroboros Peras. It also qualifies as a **Critical** bypass of Peras certificate verification, enabling unauthorized certificate acceptance that directly drives chain selection.

---

### Likelihood Explanation

The Peras certificate mini-protocol (ObjectDiffusion) is a network-facing protocol reachable by any peer. No stake, key material, or privileged access is required. The attacker only needs to construct a well-formed `PerasCert` CBOR message (the serialization format is public) and send it to a node with Peras enabled. The attack is deterministic and requires a single message.

Peras is currently disabled by default, but the code is production-ready and the feature flag is the only barrier. Once enabled on any network (testnet or mainnet), this path is immediately exploitable.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before Peras is enabled on any network. At minimum, verify: (a) the certificate's committee signatures using the appropriate BLS/VRF scheme, (b) that the voter set meets the quorum threshold from the on-chain stake distribution, (c) that `pcCertRound` is within a valid window relative to the current slot, and (d) that `pcCertBoostedBlock` refers to a block that is reachable from the current chain.

2. **Remove or gate the degenerate instance** (`instance StandardHash blk => BlockSupportsPeras blk`) so that it cannot be used in any code path that processes network input. Replace it with a compile-time error or a `Void`-returning stub that cannot be called.

3. **Add a feature-flag guard** in `processCerts` / `makePerasCertPoolWriterFromChainDB` that rejects all inbound certificates when Peras is disabled, preventing the stub from being reachable even during development.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion (Peras cert mini-protocol)
     → makePerasCertPoolWriterFromChainDB.opwAddObjects
     → processCerts systemTime alreadyInDbSTM (validatePerasCert mkPerasParams) addCert [craftedCert]
     → validatePerasCert mkPerasParams craftedCert  -- always Right
     → ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
     → chainSelSync (ChainSelAddPerasCert cert)
     → PerasCertDB.addCert  -- cert stored
     → constructPreferableCandidates with updated PerasWeightSnapshot
     → preferAnchoredCandidate sees adversarial fork as heavier
     → switchTo adversarial chain
```

**Crafted certificate structure** (CBOR, per the `Serialise` instance):

```
craftedCert = PerasCert
  { pcCertRound       = <any round not yet in DB>
  , pcCertBoostedBlock = <Point of a block on the adversarial fork>
  }
``` [7](#0-6) 

No cryptographic material is needed. The certificate passes `validatePerasCert` unconditionally, receives the full `perasWeight` boost, and is immediately used to tilt chain selection toward the adversarial fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
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
