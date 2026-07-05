### Title
Stub `validatePerasCert` Allows Unprivileged Peer to Inject Arbitrary Peras Certificates, Manipulating Chain Selection Weight - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` degenerate instance unconditionally accepts every inbound Peras certificate without performing any cryptographic or committee validation. Because the `PerasWeightSnapshot` used for chain selection is computed directly from the live `PerasCertDB` state — which includes these unvalidated certificates — an unprivileged peer can inject crafted certificates that boost arbitrary blocks, causing an honest node to prefer a non-canonical or adversarial chain over the honest chain.

This is the direct analog of the Pair-price manipulation bug: just as the Pair contract reads live token balances instead of internally tracked reserves (allowing direct transfers to bypass the K-invariant check), the Peras chain-selection path reads a weight snapshot derived from a certificate store that accepts any peer-supplied certificate (bypassing the quorum/signature invariant that should gate certificate acceptance).

---

### Finding Description

**Root cause — stub `validatePerasCert`:**

The only `BlockSupportsPeras` instance in the production codebase is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params   -- full boost, unconditionally
        }
``` [1](#0-0) 

Every certificate submitted by any peer passes validation and receives the full configured `perasWeight` boost.

**Inbound path — `processCerts`:**

Certificates received over the object-diffusion mini-protocol are processed by `processCerts`, which calls `validatePerasCert mkPerasParams`. Because the stub always returns `Right`, every certificate in the batch is accepted and forwarded to `addCert`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [2](#0-1) 

**Storage — `implAddCert` only deduplicates by round number:**

Once a certificate passes the stub validator, `implAddCert` stores it after checking only that no certificate for the same round number already exists. No check is made on the boosted block's existence, chain membership, or cryptographic integrity:

```haskell
implAddCert PerasCertDbEnv{..} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        -- certificate stored unconditionally
``` [3](#0-2) 

**Weight snapshot computed from live DB state:**

`implGetWeightSnapshot` derives the `PerasWeightSnapshot` directly from every certificate currently in `pcdsCertsByTicket`, including attacker-injected ones:

```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds) ]
  pure (WithFingerprint weights fp)
``` [4](#0-3) 

**Chain selection consumes the manipulated snapshot:**

`chainSelectionForBlock` reads the live weight snapshot atomically and passes it to `preferAnchoredCandidate` and `compareChainDiffs`. When the snapshot is non-empty (Peras active), chain comparison switches from pure block-number ordering to Peras-weighted ordering:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [5](#0-4) 

`preferAnchoredCandidate` then uses `weightedSelectView` to compare the total weight (block number + Peras boost) of the two chains:

```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights = {- standard longest-chain -}
  | otherwise =
      case AF.intersect ours cand of
        Just (_,_,oursSuffix,candSuffix) ->
          case preferCandidate cfg
                 (weightedSelectView cfg weights oursSuffix)
                 (weightedSelectView cfg weights candSuffix) of ...
``` [6](#0-5) 

An attacker who injects a certificate boosting a block on a shorter adversarial fork can make `wsvTotalWeight` of that fork exceed the honest chain's total weight, causing the node to switch.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

When Peras is enabled, a single peer can inject one certificate per round (the deduplication check only blocks a second certificate for the *same* round number). Each injected certificate adds `perasWeight` to the target block's boost. By targeting a block on an adversarial fork, the attacker can make that fork's `wsvTotalWeight` exceed the honest chain's, causing the node to switch to the adversarial chain. This directly undermines the Ouroboros chain-selection security guarantee.

---

### Likelihood Explanation

Any peer reachable via the object-diffusion mini-protocol can submit certificates. No stake, key material, or privileged access is required. The only gate — `validatePerasCert` — is a stub that always returns `Right`. The attack is therefore trivially executable by any connected peer whenever Peras is enabled. Peras is disabled by default, which limits exposure to nodes that have explicitly opted in, but the production code path is fully wired and the stub is the only protection.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` (tracked in [issue #120](https://github.com/tweag/cardano-peras/issues/120)): verify the aggregate BLS signature, confirm committee membership, and check that the total stake of signers meets the quorum threshold defined in `PerasCfg`.
2. **Validate the boosted block exists on a known chain** before accepting a certificate into the `PerasCertDB`; certificates boosting unknown or invalid blocks should be rejected.
3. **Do not enable Peras in production** until the stub is replaced with a complete implementation.

---

### Proof of Concept

1. Connect to a node with Peras enabled via the object-diffusion mini-protocol.
2. Craft a `PerasCert` whose `pcCertBoostedBlock` points to the tip of an adversarial fork that is shorter (by block count) than the honest chain.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams`, which returns `Right` unconditionally.
4. `implAddCert` stores the certificate (round number not yet seen → passes deduplication).
5. `implGetWeightSnapshot` now includes `(adversarialTip, perasWeight params)` in the snapshot.
6. On the next call to `chainSelectionForBlock` (triggered by any new block), `preferAnchoredCandidate` computes `wsvTotalWeight` for both chains. The adversarial fork's total weight (`blockNo + perasWeight`) now exceeds the honest chain's block number alone.
7. The node switches to the adversarial chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-198)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
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
