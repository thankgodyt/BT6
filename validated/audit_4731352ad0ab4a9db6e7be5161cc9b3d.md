### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) without performing any cryptographic or structural validation. Any peer can send a crafted Peras certificate over the object-diffusion mini-protocol; the certificate will be accepted, stored, and its weight boost applied to chain selection — potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the only `BlockSupportsPeras` instance in the codebase is a catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This is the **only** `BlockSupportsPeras` instance in the repository (confirmed by grep: the class and its instance appear only in `SupportsPeras.hs`; no Cardano-specific override exists). It applies to every block type, including the production Cardano block.

The production inbound path for Peras certificates is `makePerasCertPoolWriterFromChainDB` in `PerasCert.hs`, which explicitly passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

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
    ...
    }
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert` is pattern-matched: if all results are `Right`, the certificates are added; if any are `Left`, the batch is rejected. Because `validatePerasCert` always returns `Right`, the `Left` branch is unreachable — every certificate from every peer is unconditionally accepted:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Accepted certificates are forwarded to `ChainDB.addPerasCertAsync`, which enqueues a `ChainSelAddPerasCert` message. Chain selection then reads the `PerasWeightSnapshot` (populated from accepted certs) and uses it in `preferAnchoredCandidate` / `compareAnchoredFragments` to decide whether to switch chains:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
      Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
        case preferCandidate
          (projectChainOrderConfig cfg)
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix) of
          ShouldSwitch r -> ShouldSwitch (Left r)
          ShouldNotSwitch o -> ShouldNotSwitch o
``` [4](#0-3) 

The `wsvTotalWeight` used for comparison is `BlockNo + weightBoost`, where `weightBoost` is the sum of all Peras boosts on the fragment: [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `Point blk` (any block hash and slot) as the boosted block and any `PerasRoundNo`. Because `validatePerasCert` performs no signature check, no committee-membership check, and no round-validity check, the certificate is accepted and its boost (`perasWeight params`) is added to the `PerasWeightSnapshot` for that point. If the boosted point lies on a fork that is otherwise shorter than the honest chain, the artificial weight boost can make that fork appear heavier, causing the node to switch to it. This is a **chain-selection error triggered by an unprivileged peer** — the node adopts a non-canonical chain without any ledger-rule violation by the attacker.

---

### Likelihood Explanation

The attack requires only a peer connection and knowledge of the Peras certificate wire format (which is public and serialised with standard CBOR). No stake, no cryptographic keys, and no block-production capability are needed. The attacker only needs to know the hash of a block on a competing fork to boost it. The object-diffusion mini-protocol for Peras certificates is wired up in production source files (not test-only code), and `makePerasCertPoolWriterFromChainDB` is explicitly documented as the production path.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic validation before the Peras object-diffusion protocol is enabled in production. At minimum, the implementation must verify:

1. The certificate's cryptographic signature (BLS aggregate or equivalent).
2. That the signers are eligible committee members for the claimed round.
3. That the claimed round number is within the valid window relative to the current chain tip.
4. That the boosted block point exists on a known chain.

Until real validation is in place, the object-diffusion inbound handler for Peras certificates should be disabled or gated behind a feature flag that is off by default in production.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any valid-looking `PerasRoundNo`
   - `pcCertBoostedBlock` = the `Point` of a block on a competing (shorter) fork that the attacker wants the node to prefer
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams}` unconditionally.
4. The certificate is passed to `ChainDB.addPerasCertAsync`, which enqueues `ChainSelAddPerasCert`.
5. Chain selection runs with the boosted `PerasWeightSnapshot`; `preferAnchoredCandidate` now computes `wsvTotalWeight` including the injected boost for the attacker's chosen block.
6. If the boost is large enough to make the fork's total weight exceed the honest chain's total weight, the node switches to the fork. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
