### Title
`vpcCertBoost` Baked at Validation Time Creates Chain-Selection Inconsistency When `perasWeight` Changes - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

`ValidatedPerasCert` permanently stores `vpcCertBoost :: !PerasWeight` at the moment a certificate is validated or forged, using the `perasWeight` field of the current `PerasCfg`. The `PerasWeightSnapshot` that drives Peras-aware chain selection is built directly from these frozen per-certificate boost values. If `perasWeight` changes (e.g., via a protocol-parameter update once the production `PerasCfg` plumbing is wired in), certificates already in `PerasCertDB` retain the old boost while newly arriving certificates carry the new boost. The resulting mixed-weight snapshot causes chain selection to apply different effective boosts to different rounds, breaking the uniform weight assumption that the Peras security argument relies on.

### Finding Description

**Root cause — boost frozen at validation time**

Both `validatePerasCert` and `forgePerasCert` in the `BlockSupportsPeras` instance unconditionally snapshot `perasWeight params` into the returned `ValidatedPerasCert`:

```haskell
-- validatePerasCert
vpcCertBoost = perasWeight params   -- line 357

-- forgePerasCert
vpcCertBoost = perasWeight params   -- line 384
``` [1](#0-0) [2](#0-1) 

**Stored boost drives chain selection**

`PerasCertDB.Impl.implGetWeightSnapshot` builds the `PerasWeightSnapshot` by reading `getPerasCertBoost cert` (i.e., `vpcCertBoost`) for every certificate in the database:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [3](#0-2) 

That snapshot is then consumed by `preferAnchoredCandidate` / `chainSelection` to decide which candidate chain to adopt: [4](#0-3) [5](#0-4) 

**No re-validation path exists**

`PerasCertDB` stores `ValidatedPerasCert` objects and exposes no API to re-validate or recompute boosts. `implAddCert` simply inserts the already-validated certificate as-is: [6](#0-5) 

**Production entry point uses a hardcoded placeholder**

The current production writer uses `mkPerasParams` with a TODO acknowledging this will change:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [7](#0-6) 

Once the TODO is resolved and `PerasCfg` is derived from the live ledger state (as the `BlockSupportsPeras` typeclass signature already anticipates), the inconsistency becomes directly triggerable.

**Direct analogy to `setVoteFactor`**

| External report | This codebase |
|---|---|
| `voteFactor` | `perasWeight` in `PerasParams` |
| Vote tokens minted at `initializeDistributionRecord` | `vpcCertBoost` frozen at `validatePerasCert` / `forgePerasCert` |
| Tokens burned at `executeClaim` using current factor | Boost read from stored cert at chain-selection time |
| `setVoteFactor()` raises factor → burn reverts | `perasWeight` raised → old certs underweight, new certs overweight → divergent selection |

### Impact Explanation

When `perasWeight` changes between two certificate arrivals, the `PerasWeightSnapshot` contains a mix of old and new boost values. `totalWeightOfFragment` sums these heterogeneous values: [8](#0-7) 

Chain selection then compares total weights across candidate fragments using this corrupted snapshot. A chain boosted by an older certificate (carrying the old, lower weight) will be systematically undervalued relative to a chain boosted by a newer certificate, or vice versa. This breaks the Peras security invariant that every certificate of the same round contributes the same boost, and can cause honest nodes to diverge in their preferred chain — a **High** chain-selection bug.

### Likelihood Explanation

Currently **low** because `perasWeight` is hardcoded via `mkPerasParams` and all certificates receive the same boost value. The vulnerability becomes **medium-to-high** as soon as the production `PerasCfg` plumbing is completed (the TODO at line 103 of `PerasCert.hs`), at which point any on-chain governance action that updates `perasWeight` — a crafted transaction reachable without operator key compromise — triggers the inconsistency for all nodes that have already cached certificates from the prior epoch. [9](#0-8) 

### Recommendation

Do not bake `perasWeight` into `ValidatedPerasCert` at validation time. Instead:

1. Store only the raw `PerasCert` (round number + boosted block point) in `PerasCertDB`.
2. Compute the boost dynamically in `implGetWeightSnapshot` using the **current** `perasWeight` from the live `PerasCfg`, so the snapshot is always consistent with the active protocol parameters.

Alternatively, if storing the validated form is required for other reasons, invalidate and re-validate all cached certificates whenever `perasWeight` changes, analogous to how the external report's fix required resetting voting power on parameter change.

### Proof of Concept

```
Private testnet sequence:

1. Deploy node with perasWeight = W1 (e.g., 15).
2. Peer A diffuses a valid PerasCert for round R boosting block B1.
   → Node stores ValidatedPerasCert { vpcCertBoost = W1 } for round R.

3. Submit governance transaction updating perasWeight to W2 = 30.
   → New PerasCfg takes effect at next epoch boundary.

4. Peer B diffuses a valid PerasCert for round R+1 boosting block B2.
   → Node stores ValidatedPerasCert { vpcCertBoost = W2 } for round R+1.

5. implGetWeightSnapshot now returns:
     B1 → W1 = 15
     B2 → W2 = 30

6. A candidate chain containing B2 receives 30 units of boost while an
   equally long chain containing B1 receives only 15 units.
   preferAnchoredCandidate selects the B2 chain even if the Peras
   protocol, evaluated uniformly with W2, would not prefer it.

7. A second honest node that received both certs after the parameter
   change validates both with W2, giving B1 → 30 and B2 → 30, and
   may reach a different chain-selection outcome — consensus divergence.
``` [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L376-385)
```haskell
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-210)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1144)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
 where
  ChainSelEnv{..} = chainSelEnv

  sortCandidates ::
    [(ChainDiff (Header blk), ReasonForSwitch' blk)] -> [(ChainDiff (Header blk), ReasonForSwitch' blk)]
  sortCandidates = sortBy ((flip $ compareChainDiffs bcfg weights curChain) `on` fst)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-132)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)
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
