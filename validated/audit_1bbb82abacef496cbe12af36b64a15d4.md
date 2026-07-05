### Title
Peras Certificate Validation is a No-Op, Allowing Unprivileged Peers to Inject Arbitrary Chain-Selection Boosts — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or semantic checks. This is the direct analog of the external report's asymmetric-update bug: only one branch of the validation conditional is ever taken (the "valid" branch), while the "invalid" branch is structurally unreachable. An unprivileged peer can therefore inject arbitrarily crafted Peras certificates that are stored in the `PerasCertDB` and subsequently used to add artificial weight boosts to any block during chain selection, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

In `SupportsPeras.hs`, the default `BlockSupportsPeras` instance implements `validatePerasCert` as:

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

This function **always returns `Right`** regardless of the certificate's content. No BLS aggregate signature is verified, no committee membership is checked, no round-number bounds are enforced, and no boosted-block validity is confirmed. [1](#0-0) 

This function is called directly in the production certificate ingest path inside `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` is the function that handles all inbound Peras certificates received from peers. It filters out already-known rounds, then calls `validateCert` on each remaining certificate. Because `validateCert` is the no-op above, every certificate passes and is timestamped and stored: [3](#0-2) 

The stored certificates are then consumed by `getWeightSnapshot` from the `PerasCertDB`, which feeds into `preferAnchoredCandidate` via `weightedSelectView`. When the `PerasWeightSnapshot` is non-empty, chain selection switches from the standard block-number comparison to a weighted comparison that adds the certificate boost to the fragment's total weight: [4](#0-3) 

The `wsvTotalWeight` of a fragment is `blockNo + weightBoost`, so a sufficiently large injected boost can make a shorter (lower block-number) chain appear heavier than the honest chain: [5](#0-4) 

---

### Impact Explanation

**Impact: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

A malicious peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` pointing to any block on a minority fork. Because `validatePerasCert` never rejects anything, the certificate is stored and its boost is applied during chain selection. If the injected `PerasWeight` exceeds the honest chain's lead in block number, the node switches to the adversarial fork. The `SecurityParam` interpretation for Peras is total weight (block count + boost sum), so a single large-boost certificate can exceed the rollback budget `k` in weight terms and cause the node to permanently adopt the wrong chain. [6](#0-5) 

---

### Likelihood Explanation

**Likelihood: Medium** — The Peras object-diffusion mini-protocol is an active production code path reachable by any connected peer. The attacker needs only to send a well-formed CBOR-encoded `PerasCert` (the serialization decoder does perform structural checks, but no cryptographic ones). No stake, keys, or privileged access are required. The only limiting factor is that Peras chain-selection is only active when the `PerasWeightSnapshot` is non-empty, which requires at least one certificate to have been stored — a condition the attacker trivially satisfies by sending the first certificate themselves. [7](#0-6) 

---

### Recommendation

Replace the no-op `validatePerasCert` default instance with a real implementation that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. Checks that each voter in `pcVoters` is a legitimate committee member for `pcCertRound` (persistent or non-persistent with a valid VRF eligibility proof).
3. Confirms that the total stake of the voters meets the quorum threshold (`perasQuorumStakeThreshold`).
4. Validates that `pcCertBoostedBlock` refers to a block that is actually on a known chain and satisfies the minimum age (`perasBlockMinSlots`).

Until the real implementation is in place, the certificate ingest path should reject all certificates rather than accept all of them, to avoid the asymmetric-acceptance bug. [8](#0-7) 

---

### Proof of Concept

1. Connect to a node running this code as a peer via the Peras certificate object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the tip of a minority fork you want the node to adopt
   - `pcVoters` = any non-empty bitmap (structural decoder only checks non-emptiness)
   - `pcSignature` = any bytes that decode as a valid CBOR aggregate signature structure
3. Send the certificate. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
4. The certificate is stored with `vpcCertBoost = perasWeight params` (the configured boost weight).
5. On the next chain-selection event, `preferAnchoredCandidate` uses the non-empty `PerasWeightSnapshot`. The minority fork's fragment now has `blockNo + boost` total weight. If `boost` exceeds the honest chain's block-number lead, `preferCandidate` returns `ShouldSwitch` and the node adopts the adversarial fork. [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-60)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Config/SecurityParam.hs (L30-37)
```haskell
-- In weightiest-chain protocols (such as Ouroboros Peras), we interpret this as
-- the maximum amount of weight we can roll back. Here, the total weight of a
-- chain (fragment) is defined to be its length plus the sum of all weight
-- boosts given to some of its blocks on the chain (fragment).
--
-- i.e. k == 30: we can roll back at most 30 unweighted blocks, or two blocks
-- each having additional weight 14. In the latter case, the chain fragment has
-- total weight @2 + 2 * 14 = 30@.
```
