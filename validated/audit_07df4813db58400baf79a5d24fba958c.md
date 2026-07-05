### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation is an acknowledged stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or protocol-rule checks. Because this function is the sole gate between a peer-supplied `PerasCert` and the `PerasCertDB` / `PerasWeightSnapshot` that drives Peras chain selection, any unprivileged peer can inject arbitrary certificates, inflate the Peras weight of any block on any fork, and cause an honest node to switch away from the canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory validation entry point for inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only production instance (the catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements it as:

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

This stub is called directly in the production inbound-certificate pipeline via `processCerts`, which is wired into both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` applies this function to every new certificate received from a peer and, if it returns `Right`, immediately adds the result to the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Once stored, `implGetWeightSnapshot` materialises a `PerasWeightSnapshot` directly from every certificate in the `PerasCertDB`:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [5](#0-4) 

Chain selection then uses this snapshot via `weightedSelectView` / `weightBoostOfFragment` to compute `wsvTotalWeight = BlockNo + wsvWeightBoost` and calls `preferCandidate` to decide whether to switch forks:

```haskell
case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
  LT -> ShouldSwitch (Heavier $ ...)
  ...
``` [6](#0-5) 

The default `perasWeight` is `PerasWeight 15`, meaning a single injected certificate adds 15 units of weight to any targeted block. [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can send one crafted `PerasCert` per Peras round (deduplicated by `pcCertRound`), each boosting an arbitrary block on an adversarial fork by 15 weight units. Because the node's chain selection compares `BlockNo + weightBoost`, an attacker who sends `n` certificates targeting blocks on a shorter fork can make that fork appear heavier than the honest chain by up to `15n` weight units. This causes the honest node to switch to the adversarial fork, constituting a chain-selection safety failure: the node durably adopts a non-canonical chain without any stake majority or key compromise.

The `takeVolatileSuffix` function, which determines the immutability boundary, also uses the same weight snapshot, so injected boosts can additionally shrink the effective rollback window and cause premature immutability decisions. [8](#0-7) 

---

### Likelihood Explanation

The Object Diffusion mini-protocol for Peras certificates is a live network-facing component. Any connected peer can send a `PerasCert` message. The only deduplication guard is `pcCertRound` membership in the DB; a fresh round number bypasses it entirely. No stake, key, or privilege is required. The attack is repeatable every Peras round (every 90 slots by default), making sustained chain-weight manipulation straightforward.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature over `(roundNo, boostedBlock)` against the expected committee verification keys.
2. That the boosted block's slot satisfies `perasBlockMinSlots`.
3. That the certificate's round number is within `perasCertMaxRounds` of the current round.
4. That the committee membership and quorum threshold are satisfied using the epoch's stake snapshot.

Until the full cryptographic plumbing is in place, the node should refuse to accept inbound certificates from untrusted peers (i.e., disable the Object Diffusion writer for certificates in production builds), or gate acceptance behind a feature flag that is off by default.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start an honest node `H` running the Peras-enabled consensus stack.
2. Connect an adversarial peer `A` to `H` via the Object Diffusion mini-protocol.
3. `A` observes that `H`'s current chain tip is at block `B_honest` (block number `N`).
4. `A` has a fork `F` whose tip is at block `B_fork` (block number `N - 14`, i.e., 14 blocks shorter).
5. `A` sends a single `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = blockPoint B_fork }` to `H`.
6. `H`'s `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }` unconditionally.
7. The certificate is stored in `H`'s `PerasCertDB`.
8. `H`'s `implGetWeightSnapshot` now returns a snapshot with `B_fork` boosted by 15.
9. Chain selection computes: `wsvTotalWeight(honest) = N + 0 = N`; `wsvTotalWeight(fork) = (N-14) + 15 = N+1`.
10. `preferCandidate` returns `ShouldSwitch`; `H` switches to `F`.

`H` has adopted the adversarial fork with no stake majority, no key compromise, and no admin access — triggered solely by a single crafted network message. [1](#0-0) [9](#0-8) [10](#0-9) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L361-377)
```haskell
takeVolatileSuffix ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  -- | The security parameter @k@ is interpreted as a weight.
  SecurityParam ->
  AnchoredFragment h ->
  AnchoredFragment h
takeVolatileSuffix snap secParam
  | Map.null $ getPerasWeightSnapshot snap =
      -- Optimize the case where Peras is disabled.
      AF.anchorNewest (unPerasWeight k)
  | otherwise =
      takeLongestSuffix (totalWeightOfFragment snap) (<= k)
 where
  k :: PerasWeight
  k = maxRollbackWeight secParam
```
