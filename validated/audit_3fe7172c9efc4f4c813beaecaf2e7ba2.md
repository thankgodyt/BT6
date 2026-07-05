### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unprivileged Chain-Selection Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate received from a peer, performing zero cryptographic or structural checks. Because the resulting `ValidatedPerasCert` is fed directly into the `PerasCertDB` weight snapshot that drives chain selection, any unprivileged peer can inject arbitrary Peras certificates that boost any block point, causing an honest node to prefer a non-canonical chain. This is the direct analog of the `slot0` report: an unvalidated, peer-controlled value is used in a critical security calculation (chain selection) instead of a properly authenticated one.

---

### Finding Description

`BlockSupportsPeras` is the class that governs Peras certificate and vote validation. A blanket degenerate instance is provided for all block types:

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

Every `PerasCert` received from a peer is immediately wrapped in a `ValidatedPerasCert` with the configured boost weight, regardless of its content.

The inbound processing pipeline in the object-diffusion layer calls this function directly:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` iterates over all received certificates, calls `validateCert` (which is the stub above), and on success passes each one to `addCert` → `ChainDB.addPerasCertAsync`: [3](#0-2) 

`addPerasCertAsync` stores the certificate in `PerasCertDB`, which exposes `getWeightSnapshot`: [4](#0-3) 

`getWeightSnapshot` is read atomically during every chain-selection event: [5](#0-4) 

The snapshot is then passed to `preferAnchoredCandidate` / `compareChainDiffs`, which uses the accumulated Peras weight boosts to decide whether to switch forks: [6](#0-5) 

The `PerasWeightSnapshot` maps block points to `PerasWeight` values; any block point that appears in the snapshot receives a boost in chain comparison: [7](#0-6) 

The same stub pattern applies to `validatePerasVote`, which checks only that the voter ID exists in the stake distribution but verifies no cryptographic signature, allowing forged votes to accumulate toward quorum and trigger certificate forging: [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` (any `Point blk`) and any `pcCertRound`. The stub accepts it unconditionally. The resulting weight boost is added to the chain-selection snapshot. If the boosted block is on a competing fork, the honest node's `preferAnchoredCandidate` will compute a higher weight for that fork and switch to it, even if it is shorter or otherwise non-canonical. Because `PerasCertDB` deduplicates by round number, an attacker can inject one certificate per Peras round; across many rounds this accumulates enough weight to persistently override the honest chain. This matches the **High** impact tier: an unprivileged peer causes an honest node to prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is active in the production codebase and accepts inbound certificates from any connected peer. No stake, keys, or operator access are required. The `PerasCert` wire type contains only a round number and a block point — both freely chosen by the sender. The attack is deterministic and requires no brute force.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) with implementations that perform full cryptographic verification — aggregate BLS signature verification over the committee's vote-verification keys, as already implemented for the `EveryoneVotes` committee in `implVerifyCert`: [9](#0-8) 

Until real validation is wired in, the Peras certificate and vote inbound paths should be disabled or gated behind a feature flag so that the stub cannot be reached from the network.

---

### Proof of Concept

1. Attacker connects to a node via the Peras object-diffusion mini-protocol.
2. Attacker sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialPoint }` where `adversarialPoint` is the tip of a competing fork the attacker controls.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. `ChainDB.addPerasCertAsync` stores the cert; `PerasCertDB.getWeightSnapshot` now returns a non-zero boost for `adversarialPoint`.
5. When the attacker's fork block arrives, `chainSelectionForBlock` reads the snapshot, computes `weightBoostOfFragment` for the adversarial chain, and `preferAnchoredCandidate` returns `ShouldSwitch`.
6. The honest node switches to the adversarial fork.
7. Repeating with a fresh `pcCertRound` each time accumulates additional weight, making the switch increasingly difficult to reverse.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-635)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L44-57)
```haskell
-- | Data structure for tracking the weight of blocks due to Peras boosts.
newtype PerasWeightSnapshot blk = PerasWeightSnapshot
  { getPerasWeightSnapshot :: Map (Point blk) PerasWeight
  }
  deriving stock Eq
  deriving Generic
  deriving newtype NoThunks

instance StandardHash blk => Show (PerasWeightSnapshot blk) where
  show = show . perasWeightSnapshotToList

-- | An empty 'PerasWeightSnapshot' not containing any boosted blocks.
emptyPerasWeightSnapshot :: PerasWeightSnapshot blk
emptyPerasWeightSnapshot = PerasWeightSnapshot Map.empty
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```
