### Title
`completeChainDbArgs` Always Hardcodes `pvdbaPerasCfg = mkPerasParams`, Ignoring Any Configured Peras Parameters — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs`)

---

### Summary

`completeChainDbArgs` unconditionally overwrites the `pvdbaPerasCfg` field of `PerasVoteDbArgs` with the hardcoded `mkPerasParams` value, silently discarding any Peras parameters that a caller may have placed in `defArgs`. When Peras is enabled, the vote-DB uses these hardcoded parameters — including the quorum stake threshold and the per-certificate weight boost — for every certificate-forging decision, regardless of what the deployment actually requires.

---

### Finding Description

In `completeChainDbArgs`:

```haskell
, cdbPerasVoteDbArgs =
    PerasVoteDB.PerasVoteDbArgs
      { PerasVoteDB.pvdbaTracer  = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
      , PerasVoteDB.pvdbaPerasCfg = mkPerasParams          -- always hardcoded
      }
``` [1](#0-0) 

The `pvdbaTracer` is correctly forwarded from `defArgs`, but `pvdbaPerasCfg` is always replaced with `mkPerasParams`. The `PerasVoteDbArgs` record explicitly marks `pvdbaPerasCfg` as `noDefault` (must be provided by the caller):

```haskell
defaultArgs :: Applicative m => Incomplete PerasVoteDbArgs m blk
defaultArgs =
  PerasVoteDbArgs
    { pvdbaTracer    = nullTracer
    , pvdbaPerasCfg  = noDefault
    }
``` [2](#0-1) 

Yet `completeChainDbArgs` never reads `pvdbaPerasCfg` from `defArgs`; it always supplies `mkPerasParams`. The hardcoded bundle fixes, among other things:

- `perasQuorumStakeThreshold = 3/4`
- `perasQuorumStakeThresholdSafetyMargin = 2/100`
- `perasWeight = 15` [3](#0-2) 

These hardcoded values are then passed directly into `implAddVote` as `perasCfg`:

```haskell
createDB args@PerasVoteDbArgs{pvdbaPerasCfg} = do
  ...
  pure PerasVoteDB
    { addVote = implAddVote pvdbaPerasCfg env
    ...
    }
``` [4](#0-3) 

Inside `implAddVote`, `perasCfg` is forwarded to `updatePerasRoundVoteStates`, which uses it to decide whether a quorum has been reached and a certificate should be forged:

```haskell
implAddVote perasCfg PerasVoteDbEnv{..} vote = do
  ...
  case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
    Right (VoteGeneratedNewCert cert, ...) -> ...
``` [5](#0-4) 

The forged certificate is then fed into chain selection, where it boosts the certified block's weight:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights = ...   -- Peras disabled path
  | otherwise = ...                            -- Peras enabled: uses wsvWeightBoost
``` [6](#0-5) 

---

### Impact Explanation

When Peras is enabled via `rnFeatureFlags`, the hardcoded `perasQuorumStakeThreshold = 3/4` governs every certificate-forging decision. If the deployment's actual protocol parameters require a stricter threshold (e.g., 4/5), an adversary controlling ≥ 3/4 of the stake — but less than 4/5 — can submit votes that cause the node to forge a certificate it should not forge. That certificate then boosts the adversary's block in `preferAnchoredCandidate`, potentially causing the honest node to switch to a non-canonical chain. Conversely, if the deployment requires a looser threshold, legitimate certificates are never forged, stalling Peras settlement. Either way, the chain-selection invariant is violated by a crafted sequence of network-delivered votes, with no operator key compromise required.

The weight boost (`perasWeight = 15`) is similarly hardcoded. A wrong boost value directly distorts `wsvTotalWeight` comparisons in `WeightedSelectView.preferCandidate`, making chain selection diverge from the protocol's intended security assumptions.

---

### Likelihood Explanation

Peras is currently disabled by default (`rnFeatureFlags` does not enable it). The bug is latent but structurally guaranteed to fire whenever Peras is activated: `completeChainDbArgs` is on the mandatory initialization path for every node, and the overwrite is unconditional. Any private testnet or future mainnet deployment that enables Peras will silently use the hardcoded parameters.

---

### Recommendation

Pass the Peras configuration as an explicit parameter to `completeChainDbArgs` (analogous to how `immChunkInfo` and `checkIntegrity` are passed), and use it instead of the hardcoded `mkPerasParams`:

```haskell
completeChainDbArgs
  ...
  perasCfg          -- new explicit parameter
  defArgs =
    defArgs
      { ...
      , cdbPerasVoteDbArgs =
          PerasVoteDB.PerasVoteDbArgs
            { PerasVoteDB.pvdbaTracer   = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
            , PerasVoteDB.pvdbaPerasCfg = perasCfg   -- use the supplied value
            }
      , ...
      }
```

Alternatively, derive the Peras configuration from `cdbsTopLevelConfig` (which is already a required parameter of `completeChainDbArgs`) so that the parameters are always consistent with the rest of the node's configuration.

---

### Proof of Concept

1. Enable Peras via `rnFeatureFlags` on a private testnet node.
2. Customize `llrnChainDbArgsDefaults` to set `pvdbaPerasCfg` to a `PerasParams` with `perasQuorumStakeThreshold = 4/5`.
3. Start the node; observe via tracing that `completeChainDbArgs` overwrites the field — the vote DB is initialized with `mkPerasParams` (threshold 3/4), not the configured 4/5.
4. Submit votes from a set of keys controlling exactly 3/4 of the stake for a target block.
5. Observe that `implAddVote` calls `updatePerasRoundVoteStates` with the hardcoded 3/4 threshold, declares quorum reached, and forges a certificate — even though the configured threshold of 4/5 was not met.
6. The certificate is added to the `PerasCertDB` and triggers `chainSelSync`, boosting the target block by `perasWeight = 15` in `preferAnchoredCandidate`, causing the node to switch to the adversary's chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L229-233)
```haskell
      , cdbPerasVoteDbArgs =
          PerasVoteDB.PerasVoteDbArgs
            { PerasVoteDB.pvdbaTracer = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
            , PerasVoteDB.pvdbaPerasCfg = mkPerasParams
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L130-135)
```haskell
defaultArgs :: Applicative m => Incomplete PerasVoteDbArgs m blk
defaultArgs =
  PerasVoteDbArgs
    { pvdbaTracer = nullTracer
    , pvdbaPerasCfg = noDefault
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L145-162)
```haskell
createDB args@PerasVoteDbArgs{pvdbaPerasCfg} = do
  pvdeState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasVoteDbState)
      initialPerasVoteDbState
  let env =
        PerasVoteDbEnv
          { pvdeTracer
          , pvdeState
          }
  pure
    PerasVoteDB
      { addVote = implAddVote pvdbaPerasCfg env
      , getVoteIds = implGetVoteIds env
      , getVotesAfter = implGetVotesAfter env
      , getForgedCertForRound = implGetForgedCertForRound env
      , garbageCollect = implGarbageCollect env
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L183-210)
```haskell
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L154-177)
```haskell
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
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
