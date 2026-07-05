### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Allows Unprivileged Peer to Manipulate Chain Selection Weights — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance for `StandardHash blk` implements `validatePerasCert` as a stub that unconditionally accepts every inbound certificate without performing any cryptographic or committee-membership verification. This stub is wired directly into the production certificate ingestion path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can therefore inject arbitrary crafted `PerasCert` objects that are stored in `PerasCertDB` and subsequently used to assign weight boosts to arbitrary blocks during chain selection, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional acceptance in `validatePerasCert`:**

The default instance for all `StandardHash blk` blocks in `SupportsPeras.hs` (lines 350–358) implements `validatePerasCert` as:

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

There is no check on the certificate's cryptographic signature, no committee-membership verification, no round-number plausibility check, and no check that the boosted block actually exists on any known chain. Every certificate, regardless of content or origin, is returned as `Right` (valid).

**Production wiring — `processCerts` and `makePerasCertPoolWriterFromChainDB`:**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` (lines 113–137) is the production path that processes certificates received from peers via the object-diffusion mini-protocol. It passes the stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
```

`processCerts` (lines 156–185) calls this validator on every inbound certificate not already in the database. Because the stub always returns `Right`, every certificate passes and is stored via `ChainDB.addPerasCertAsync`.

**Chain selection impact — `preferAnchoredCandidate`:**

`preferAnchoredCandidate` in `AnchoredFragment.hs` (lines 186–213) has two branches. When `isEmptyPerasWeightSnapshot weights` is `False` (i.e., at least one certificate has been stored), it switches to Peras-weighted chain selection:

```haskell
| otherwise =
    case AF.intersect ours cand of
      ...
        case preferCandidate
          (projectChainOrderConfig cfg)
          (weightedSelectView cfg weights oursSuffix)
          (weightedSelectView cfg weights candSuffix) of
```

The `weights` come from `PerasCertDB.getWeightSnapshot`, which returns boosts for every stored certificate. An attacker who injects a certificate boosting a block on their own fork causes `weightedSelectView` to return a higher value for that fork, making `preferCandidate` return `ShouldSwitch`, and the honest node adopts the attacker's chain.

**Exploit path (end-to-end):**

1. Attacker peer connects to an honest node via the object-diffusion mini-protocol.
2. Attacker sends a batch of crafted `PerasCert` objects, each claiming to boost a block on the attacker's fork for a given `PerasRoundNo`.
3. `processCerts` filters out round numbers already in the DB, then calls `validatePerasCert mkPerasParams` on the remainder — the stub returns `Right` for all of them.
4. Each certificate is timestamped and stored via `ChainDB.addPerasCertAsync`.
5. `implGetWeightSnapshot` assembles a `PerasWeightSnapshot` that now includes the attacker's boosts.
6. On the next chain selection event, `preferAnchoredCandidate` uses the poisoned weight snapshot; the attacker's fork, boosted by fabricated certificates, is preferred over the honest chain.

---

### Impact Explanation

**High — Chain selection bug.** An unprivileged peer with a network connection can make an honest node prefer a non-canonical, attacker-controlled chain by injecting fabricated Peras certificates. Because `validatePerasCert` performs zero verification, the attacker needs no keys, no stake, and no committee membership. The weight boost applied to the attacker's fork is `perasWeight params` per injected certificate, which can be made arbitrarily large by sending multiple certificates for different round numbers. This directly violates the Peras security assumption that only legitimately elected committee members can issue weight-bearing certificates.

---

### Likelihood Explanation

**Medium-High.** The object-diffusion mini-protocol is reachable by any peer that can establish a connection to the node. No privileged access is required. The only precondition is that Peras certificate diffusion is active (the code is already wired into `NodeKernel` via `makePerasCertPoolWriterFromChainDB`). The TODO comments confirm the stub is intentionally temporary, but it is currently deployed in production files with no runtime guard disabling it.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate's aggregate BLS/VRF signature against the registered committee keys for the claimed round.
2. Checks that the claimed voters are eligible members of the committee for that round (using the stake distribution snapshot from the ledger).
3. Verifies that the boosted block's point is a known, valid block on a chain the node has seen.
4. Enforces that only one certificate per round number is accepted (the current `Set.member` deduplication is insufficient if the first accepted certificate is itself forged).

Until the real implementation is in place, the production wiring in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` should use a validator that rejects all certificates (returning `Left PerasValidationErr` unconditionally) rather than accepting all of them.

---

### Proof of Concept

```
Attacker node A connects to honest node H.

A sends via object-diffusion:
  [ PerasCert { pcCertRound = 42, pcCertBoostedBlock = <attacker fork tip> }
  , PerasCert { pcCertRound = 43, pcCertBoostedBlock = <attacker fork tip> }
  , ...
  ]

H calls processCerts:
  alreadyInDb = {} (empty, first contact)
  certsNotAlreadyInDb = all 3 certs
  validateCert = validatePerasCert mkPerasParams
  -- stub returns Right for every cert
  validatedCerts = [ValidatedPerasCert{vpcCert=..., vpcCertBoost=perasWeight params}, ...]
  -- all stored via ChainDB.addPerasCertAsync

Next chain selection on H:
  weights = getWeightSnapshot  -- now contains boosts for attacker's fork tip
  isEmptyPerasWeightSnapshot weights = False
  preferAnchoredCandidate uses weightedSelectView:
    weightedSelectView cfg weights candSuffix  -- attacker's suffix has boost
    > weightedSelectView cfg weights oursSuffix -- honest suffix has no boost
  => ShouldSwitch: H adopts attacker's fork
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
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
