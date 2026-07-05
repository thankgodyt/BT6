### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peras Certificate, Enabling Unauthorized Chain Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that always returns `Right` (success) without performing any cryptographic or semantic validation. An unprivileged peer can exploit this via the Peras object-diffusion mini-protocol to inject arbitrary certificates, manipulating the `PerasWeightSnapshot` used in chain selection and causing an honest node to prefer a non-canonical, adversarially-boosted chain.

---

### Finding Description

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` (lines 318–358) is explicitly marked as a "degenerate instance for all blks to get things to compile." Its `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, assigning it the full configured `perasWeight` boost without checking any cryptographic proof, round number validity, committee membership, or aggregate BLS signature:

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

This stub is wired directly into the network-facing certificate ingestion path. `makePerasCertPoolWriterFromChainDB` (the production writer used by the ChainDB) passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` is the inbound handler for Peras certificates received from remote peers over the object-diffusion mini-protocol. It calls `validateCert` on each certificate and, if all pass, adds them to the database. Because the stub always returns `Right`, the `(errs, _)` branch that would throw `PerasCertInboundException` and disconnect the peer is **never reached**: [3](#0-2) 

Once accepted, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which calls `chainSelSync`. That function adds the certificate to `PerasCertDB`, reads the boosted block from the VolatileDB, and immediately triggers `chainSelectionForBlock` for the adversarially-chosen block: [4](#0-3) 

The `PerasCertDB`'s `getWeightSnapshot` then returns a `PerasWeightSnapshot` that includes the injected boost. Chain selection uses this snapshot in two critical ways:

1. **`forksAtMostKWeight`** — checks whether the weight of the suffix of the current chain after the intersection with a candidate is `<= k`. If an attacker injects certificates boosting blocks on the current chain, the rollback weight of a legitimate competing fork can be made to appear to exceed `k`, causing the node to permanently reject the honest fork. [5](#0-4) 

2. **`compareAnchoredFragments` / `preferCandidate`** — compares `wsvTotalWeight` (block number + weight boost) of competing fragments. An attacker who injects a certificate boosting a non-canonical block can make that block's fragment heavier than the canonical chain, causing the node to switch to the adversarial fork. [6](#0-5) 

The `PerasVote` data type (also in the same stub instance) carries no signature field at all, and `validatePerasVote` performs no cryptographic check either — only a stake-distribution lookup — meaning an attacker can also forge votes from any known voter ID to manufacture a quorum and generate a certificate locally. Both paths converge on the same unauthenticated `PerasWeightSnapshot` manipulation. [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote validation enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can craft a `PerasCert` naming any block point and any round number. Because `validatePerasCert` always succeeds, the certificate is accepted, stored, and its boost is immediately reflected in the `PerasWeightSnapshot`. Depending on the configured `perasWeight` value, a single injected certificate can:

- Make a non-canonical fork heavier than the honest chain, causing the node to switch to the adversarial chain (consensus safety failure / chain selection error).
- Inflate the rollback weight of the current chain's suffix beyond `k`, causing the node to permanently reject a legitimate competing chain that forks from it (irreversible divergence from the canonical chain).

Both outcomes constitute a consensus safety failure reachable by a single unprivileged peer with no stake, no keys, and no prior relationship with the target node.

---

### Likelihood Explanation

**Medium.** Peras is under active development and not yet deployed on Cardano mainnet, but the code is in the production source tree, wired into the live object-diffusion mini-protocol handler, and exercisable on any private testnet or pre-production environment running this codebase. The attack requires only the ability to connect to the node's peer port and send a well-formed CBOR-encoded `PerasCert` message — no stake, no cryptographic material, and no special privileges. The stub is explicitly flagged with TODO comments referencing open GitHub issues, confirming the missing validation is a known gap rather than an intentional design choice.

---

### Recommendation

1. **Implement real `validatePerasCert`**: verify the aggregate BLS signature over `(roundNo, boostedBlock)`, confirm the certificate's round is within the valid window, and check that the signing committee meets the quorum threshold against the stake distribution from the relevant epoch's ledger state.
2. **Implement real `validatePerasVote`**: add a signature field to `PerasVote` and verify it before accepting the vote into the aggregation state.
3. **Until real validation is in place**, gate the object-diffusion certificate and vote handlers behind a feature flag so they are unreachable on any network where Peras is not fully specified and deployed.
4. **Add a property test** asserting that `validatePerasCert` rejects certificates with invalid or missing signatures, to prevent regression once the real implementation lands.

---

### Proof of Concept

On a private testnet running this codebase with Peras enabled:

1. Attacker connects to an honest node as a peer via the standard node-to-node mini-protocol stack.
2. Attacker observes the VolatileDB (or ChainSync headers) to learn the hash of a block `B` on a non-canonical fork at slot `s`.
3. Attacker sends a `PerasCert { pcCertRound = r, pcCertBoostedBlock = BlockPoint s (hash B) }` via the Peras object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally. [8](#0-7) 
5. The certificate is added to `PerasCertDB`; `implGetWeightSnapshot` now returns a snapshot with `B` boosted by `perasWeight`. [9](#0-8) 
6. `chainSelSync` triggers `chainSelectionForBlock` for `B`; `compareAnchoredFragments` now computes `wsvTotalWeight` of the fork containing `B` as `blockNo(B) + perasWeight`, which may exceed the canonical chain's total weight. [10](#0-9) 
7. The honest node switches to the adversarial fork, or — if the attacker instead boosts blocks on the current chain — permanently rejects a legitimate competing chain whose rollback weight now exceeds `k`. [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L85-89)
```haskell
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
