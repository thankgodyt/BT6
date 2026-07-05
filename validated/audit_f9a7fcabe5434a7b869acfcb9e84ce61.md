### Title
Stub `validatePerasCert` Always Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthenticated Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives, regardless of committee membership, cryptographic authenticity, or quorum proof. Because this stub is wired into the live Peras certificate diffusion pipeline, any unprivileged peer can inject an arbitrary `PerasCert` that references any block point, have it accepted without any check, and thereby inject a weight boost into the node's `PerasWeightSnapshot`. Chain selection then uses that snapshot to compare candidate fragments, so the attacker can make the node prefer a non-canonical chain whose total weight (block count + injected boost) exceeds the honest chain's weight.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must authenticate a certificate before it enters the node's state. The shipped default instance is an acknowledged stub:

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

This stub is the **only** validation gate in the inbound certificate path. `processCerts` in `PerasCert.hs` calls the supplied `validateCert` function (which is `validatePerasCert mkPerasParams`) and, if it returns `Right`, timestamps the certificate and stores it:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` — the writer used in the live diffusion pipeline — explicitly passes `validatePerasCert mkPerasParams` as the validator: [3](#0-2) 

The stored `ValidatedPerasCert` values feed the `PerasWeightSnapshot`. Chain selection reads this snapshot in `preferAnchoredCandidate` and, when the snapshot is non-empty, switches from pure block-count comparison to weighted comparison:

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

`wsvTotalWeight` is `blockNo + weightBoost`, so a sufficiently large injected boost can make a shorter adversarial chain outweigh the honest chain: [5](#0-4) 

The same `weights` snapshot is also used in `ChainSel.hs` to filter and sort candidates before full block validation: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer connected via the Peras certificate diffusion mini-protocol can craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork. Because `validatePerasCert` always returns `Right`, the certificate is stored and contributes `perasWeight params` to that block's entry in the `PerasWeightSnapshot`. Once the snapshot is non-empty, `preferAnchoredCandidate` switches to weighted comparison for all chain selection decisions. A chain whose total weight (block count + accumulated fake boosts) exceeds the honest chain's total weight will be selected, causing the node to roll back to and adopt the adversarial fork. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended Ouroboros security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is wired into the node-to-node layer (`aPerasCertDiffusionClient` / `aPerasCertDiffusionServer`), so any peer that can establish a connection can send certificates. The stub is the **default instance** applied to all block types (`instance StandardHash blk => BlockSupportsPeras blk`), meaning no block type currently performs real validation. No special privilege, key material, or stake is required — only a network connection. [7](#0-6) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate was issued by a legitimate Peras committee member (committee membership check against the stake distribution / committee selection context).
2. Verifies the cryptographic signature(s) on the certificate.
3. Verifies the certificate represents a genuine quorum of valid votes for the claimed round and block.

Until a real implementation is available, the certificate diffusion server should refuse all inbound certificates (return a permanent error) rather than silently accepting them with a no-op validator, analogous to how the Velodrome fix required all router interactions to use only registry-approved factories.

---

### Proof of Concept

1. Attacker peer connects to an honest node via the Peras certificate diffusion mini-protocol.
2. Attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }` where `adversarialBlockPoint` is the tip of a shorter adversarial fork the attacker is also serving via ChainSync.
3. Attacker sends the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
4. The certificate is stored; `PerasWeightSnapshot` now maps `adversarialBlockPoint` to a non-zero `PerasWeight`.
5. When the honest node's chain selection next runs, `preferAnchoredCandidate` detects a non-empty weight snapshot and switches to weighted comparison. The adversarial fragment's `wsvTotalWeight = blockNo + injectedBoost` exceeds the honest chain's `wsvTotalWeight = blockNo + 0`.
6. The honest node selects the adversarial chain, rolling back its ledger state to the fork point and adopting the attacker's blocks. [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L61-68)
```haskell
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L775-778)
```haskell
    | chain <- fragments
    , -- Only keep candidates preferable to the current chain.
    ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain $ Diff.getSuffix chain]
    ]
```
