### Title
Peras Certificate and Vote Verification Bypass via Stub `validatePerasCert`/`validatePerasVote` — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used in production code unconditionally accepts every inbound Peras certificate without any cryptographic validation, and accepts votes without verifying their signatures. An unprivileged peer can inject crafted certificates or forged votes that are stored in `PerasCertDB`/`PerasVoteDB` and influence chain selection, analogous to how the symmio `chargeFundingRate` function modified nonces without meaningful validation of its inputs.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` is a degenerate placeholder that compiles for all block types. Its `validatePerasCert` implementation unconditionally returns `Right` for any certificate:

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

Similarly, `validatePerasVote` only checks stake-distribution membership and never verifies the vote signature:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

These stubs are wired directly into the production inbound-object pipeline. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback: [3](#0-2) 

`processCerts` then calls that callback on every certificate received from a peer, and any certificate that passes (i.e., all of them) is timestamped and stored in `PerasCertDB`: [4](#0-3) 

The same pattern applies to votes: `makePerasVotePoolWriterFromChainDB` passes `validatePerasVote mkPerasParams sd vote` as the validator, and `processVotes` stores every vote that passes (i.e., any vote whose voter ID appears in the stake distribution): [5](#0-4) 

Once stored, certificates affect chain selection via `getWeightSnapshot` in `PerasCertDB`, which feeds Peras boost weights into the chain-selection logic: [6](#0-5) 

And `implAddCert` unconditionally updates `pcdsLatestCertSeen`, which is the field that gates whether a node votes in subsequent rounds: [7](#0-6) 

---

### Impact Explanation

**Certificate bypass (Critical):** Any peer can send a `PerasCert` claiming to boost an arbitrary block for an arbitrary round. Because `validatePerasCert` returns `Right` unconditionally, the certificate is stored, its boost weight is applied to chain selection, and `getLatestCertSeen` is updated. This lets an adversary make an honest node prefer a non-canonical chain by injecting certificates that artificially inflate the Peras weight of a weaker chain.

**Vote bypass (Critical):** Any peer can send a `PerasVote` with a forged signature for any registered stake pool. Because `validatePerasVote` only checks stake-distribution membership and never calls `verifyVoteSignature`, the vote is accepted as `ValidatedPerasVote`. Enough such forged votes trigger `updatePerasRoundVoteStates` → `votesReachQuorum` → `forgePerasCert`, producing a fraudulent certificate that then affects chain selection.

Both paths are reachable by an unprivileged network peer with no keys, no stake, and no operator access.

---

### Likelihood Explanation

The Peras vote and certificate diffusion mini-protocols are open to any connected peer. The degenerate instance is the only `BlockSupportsPeras` instance in the codebase and is used in the production `NodeKernel` pipeline. Any peer that can establish a connection and send well-formed CBOR-encoded `PerasVote` or `PerasCert` messages can trigger this path. No special privileges are required.

---

### Recommendation

1. **`validatePerasCert`** must verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed voters, check that the voters bitmap is non-empty, and confirm that the claimed voters collectively exceed the quorum threshold. The `fromCompactRepr` function in `Peras.Cert.V1` already rejects an empty bitmap; the cryptographic check is the missing piece.

2. **`validatePerasVote`** must call `verifyVoteSignature` (or the appropriate `Committee.Class.verifyVote`) to confirm the vote's signature before accepting it as `ValidatedPerasVote`. Stake-distribution membership is a necessary but not sufficient condition.

3. Until real validation is in place, the inbound pipelines (`processVotes`, `processCerts`) should refuse all inbound Peras objects rather than silently accepting them, to avoid deploying a node that accepts fraudulent consensus state.

---

### Proof of Concept

1. Connect to a node running this code as a peer via the Peras certificate diffusion mini-protocol.
2. Send a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = <hash of attacker-chosen block>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}`.
4. `implAddCert` stores the certificate; `pcdsLatestCertSeen` is updated to this fraudulent cert.
5. `getWeightSnapshot` now returns a non-zero Peras boost for the attacker-chosen block.
6. Chain selection on the honest node now treats the attacker-chosen block as having extra Peras weight, potentially causing it to prefer a non-canonical chain.

For votes: repeat with `PerasVote` messages using any registered pool's `KeyHash` as `pvVoteVoterId` and an arbitrary signature. Enough such messages trigger `forgePerasCert` internally, producing a fraudulent certificate via step 3–6 above. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-68)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
  , getLatestCertSeen ::
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
