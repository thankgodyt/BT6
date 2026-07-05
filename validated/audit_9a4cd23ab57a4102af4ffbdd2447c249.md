### Title
Degenerate `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Peras Weight Manipulation and Chain Selection Bypass — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass provides a catch-all degenerate instance for all `StandardHash blk` types. Its `validatePerasCert` implementation unconditionally returns `Right` — accepting every certificate without performing any cryptographic or semantic validation. Because this is the instance used in the current production codebase, any unprivileged peer can inject an arbitrary `PerasCert` over the network, have it accepted as valid, and thereby manipulate the `PerasWeightSnapshot` that drives Peras-weighted chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:** [1](#0-0) 

The degenerate instance is declared as:

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
```

No signature check, no committee membership check, no round-number bounds check, no boosted-block plausibility check — every certificate is stamped `ValidatedPerasCert` and returned as `Right`.

**Network entry path — `processCerts` calls `validateCert` on peer-supplied data:** [2](#0-1) 

`processCerts` receives raw `PerasCert` objects from a remote peer, calls the supplied `validateCert` function (which resolves to the degenerate `validatePerasCert`), and — because it always returns `Right` — immediately passes every certificate to `addCert`.

**Weight snapshot is derived directly from accepted certificates:** [3](#0-2) 

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` by iterating over every certificate stored in `pcdsCertsByTicket`. There is no secondary validation at this stage; whatever was accepted by `validatePerasCert` contributes its `vpcCertBoost` to the snapshot.

**Chain selection consumes the snapshot directly:** [4](#0-3) 

`chainSelectionForBlock` reads the `PerasWeightSnapshot` atomically and uses it to rank candidate chains via `preferAnchoredCandidate`. A boosted block on a fork can therefore cause the node to switch away from the honest chain.

**`implAddCert` also carries the same TODO:** [5](#0-4) 

The comment `-- TODO: we will need to update this method with non-trivial validation logic` confirms that the entire certificate-acceptance pipeline is intentionally incomplete.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block hash as `pcCertBoostedBlock` and any `PerasRoundNo`. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its boost is added to the `PerasWeightSnapshot`. Chain selection then uses `wsvTotalWeight = BlockNo + WeightBoost` to rank candidates: [6](#0-5) 

By injecting a certificate that boosts a block on an adversarial fork, the attacker can make that fork appear heavier than the honest chain, causing the victim node to switch to it. This is a **chain-selection safety failure** driven by unauthorized certificate acceptance — matching the "Critical / High" impact tiers in the allowed scope.

---

### Likelihood Explanation

The attack requires only:
1. A TCP connection to the victim node's Peras cert diffusion mini-protocol endpoint.
2. The ability to serialize a valid-looking `PerasCert` CBOR structure (the serialization format is public and straightforward).
3. No stake, no keys, no prior relationship with the node.

The degenerate instance is the only `BlockSupportsPeras` instance present in the codebase for the block types used in production; no overlapping instance with real validation exists.

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that:
- Verifies the aggregate BLS signature against the committee's aggregate public key for the claimed round.
- Checks that the `pcCertRound` is within the acceptable window relative to the current slot.
- Confirms that the `pcCertBoostedBlock` refers to a block that is plausibly on a recent chain (e.g., not older than the immutable tip).
- Validates committee membership and quorum threshold.

Until the real implementation is in place, the `addPerasCertAsync` / `processCerts` path should refuse all externally-supplied certificates (or gate them behind a feature flag), rather than accepting them unconditionally.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer  ──[PerasCert CBOR]──►  processCerts
                                  │
                                  ▼
                          validatePerasCert params cert
                          = Right (ValidatedPerasCert cert boost)   ← always
                                  │
                                  ▼
                          addCert (WithArrivalTime now validatedCert)
                                  │
                                  ▼
                          implAddCert → pcdsCertsByTicket updated
                                  │
                                  ▼
                          implGetWeightSnapshot
                          → PerasWeightSnapshot boosted at attacker's block
                                  │
                                  ▼
                          chainSelectionForBlock
                          → preferAnchoredCandidate uses boosted weight
                          → node switches to adversarial fork
```

**Minimal crafted certificate (pseudocode):**

```haskell
craftedCert :: PerasCert blk
craftedCert = PerasCert
  { pcCertRound      = PerasRoundNo 1          -- any round
  , pcCertBoostedBlock = blockPoint adversarialTip  -- attacker's fork tip
  }
-- validatePerasCert params craftedCert == Right (ValidatedPerasCert ...)
-- No signature, no committee proof needed.
```

The `vpcCertBoost` assigned is `perasWeight params` — the full protocol-configured boost — making the adversarial fork immediately heavier than the honest chain by that amount.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-634)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
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
