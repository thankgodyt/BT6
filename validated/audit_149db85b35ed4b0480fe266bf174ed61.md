### Title
`validatePerasCert` Unconditionally Accepts All Peras Certificates Without Validation, Enabling Chain Selection Manipulation via Crafted Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or protocol checks whatsoever. This is the validation callback wired into the live Peras certificate object-diffusion mini-protocol writer. Any unprivileged peer can therefore send crafted `PerasCert` messages that boost arbitrary blocks, directly manipulating chain selection to prefer non-canonical forks.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasCert` as:

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

No signature is verified, no committee membership is checked, no round validity is enforced. Every certificate, regardless of content, is returned as `Right ValidatedPerasCert` with a boost of `perasWeight params` (= `PerasWeight 15` from `mkPerasParams`). [2](#0-1) 

**Wiring into the live mini-protocol writer:**

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass this stub directly as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

**`processCerts` relies entirely on the validation callback:**

`processCerts` partitions inbound certificates into `Left` (invalid) and `Right` (valid). Since `validatePerasCert` never returns `Left`, every certificate passes and is forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [5](#0-4) 

**Accepted certificates directly influence chain selection:**

`implGetWeightSnapshot` builds the `PerasWeightSnapshot` from every certificate in `pcdsCertsByTicket`, including attacker-injected ones:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [6](#0-5) 

This snapshot is consumed by `preferAnchoredCandidate` and `rollbackExceedsSuffix` during every chain selection invocation: [7](#0-6) [8](#0-7) 

**Weight accumulation is unbounded per block:**

`implAddCert` deduplicates only by round number (`pcdsCertIds`). An attacker can send N certificates with distinct `pcCertRound` values all pointing to the same `pcCertBoostedBlock`. `addToPerasWeightSnapshot` uses `Map.insertWith (<>)` which sums weights for the same point, so the target block accumulates `PerasWeight (15 * N)`. [9](#0-8) [10](#0-9) 

---

### Impact Explanation

**High — Chain selection manipulation by an unprivileged peer.**

A peer sends N crafted `PerasCert` messages (each with a distinct `pcCertRound`, all with the same `pcCertBoostedBlock` pointing to a block on a minority fork). Each passes `validatePerasCert` unconditionally. The target block accumulates `PerasWeight (15 * N)`. Since `totalWeightOfFragment = length + boost`, a fork with even a single block but boost 15 outweighs a 15-block honest chain with no boost. The node switches to the attacker's preferred fork. This is a direct chain selection safety failure: an honest node is made to prefer a non-canonical chain through a crafted network message, with no stake or key compromise required.

---

### Likelihood Explanation

The Peras certificate object-diffusion mini-protocol is reachable by any peer that can establish a connection. The `PerasCert` wire format is a simple 2-field CBOR structure (`pcCertRound :: PerasRoundNo`, `pcCertBoostedBlock :: Point blk`), trivially constructable without any cryptographic material. [11](#0-10) 

---

### Recommendation

1. **Implement real validation in `validatePerasCert`**: verify the aggregate BLS signature against the committee's public keys, check committee membership and quorum, and enforce round validity constraints before returning `Right`.
2. **Gate the mini-protocol**: until proper validation is in place, disable or gate the Peras certificate diffusion mini-protocol so it is not reachable from untrusted peers in any deployment where Peras weight influences chain selection.
3. **Track the open issue**: the existing TODO references `https://github.com/tweag/cardano-peras/issues/120` — this issue must be resolved before the Peras certificate diffusion path is exposed to production peers. [12](#0-11) 

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Construct N `PerasCert` CBOR messages, each with a distinct `pcCertRound` (e.g., rounds 1 through N) and `pcCertBoostedBlock` pointing to a block on a minority fork `F`.
3. Send the batch. `processCerts` calls `validatePerasCert mkPerasParams` on each → all return `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
4. All N certs are stored in `PerasCertDB`. `implGetWeightSnapshot` computes `PerasWeight (15 * N)` for the block on fork `F`.
5. On the next chain selection event (e.g., a new block arrives), `preferAnchoredCandidate` computes `totalWeightOfFragment` for fork `F` including the accumulated boost. For N ≥ 1, fork `F` with 1 block and boost 15 outweighs the honest chain with up to 15 blocks and no boost.
6. The node switches to fork `F`.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Fragment/Diff.hs (L90-98)
```haskell
rollbackExceedsSuffix weights curChain (ChainDiff nbRollback suffix) =
  weightOf suffixToRollBack > weightOf suffix
 where
  suffixToRollBack = AF.anchorNewest nbRollback curChain

  weightOf ::
    (HasHeader b, HeaderHash b ~ HeaderHash b0) =>
    AnchoredFragment b -> PerasWeight
  weightOf = totalWeightOfFragment weights
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
