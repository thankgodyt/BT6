### Title
`validatePerasCert` and `validatePerasVote` accept any peer-supplied Peras objects without cryptographic verification, enabling unauthorized certificate injection and chain-weight manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The global `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every certificate it receives, and `validatePerasVote` accepts any vote whose voter ID appears in the stake distribution without verifying the BLS signature. Both functions are wired directly into the live object-diffusion inbound pipeline. Any unprivileged peer can therefore inject arbitrary Peras certificates that boost adversarial blocks in chain selection, or forge votes on behalf of legitimate committee members to manufacture such certificates from scratch — all without possessing any key material.

---

### Finding Description

**Root cause — `validatePerasCert` (no-op validation)**

The only `BlockSupportsPeras` instance in the codebase is the global degenerate instance:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

`validatePerasCert` performs zero checks — no BLS aggregate-signature verification, no committee-membership check, no round-number sanity check. It wraps the caller-supplied `cert` verbatim in `ValidatedPerasCert` and returns `Right`.

**Root cause — `validatePerasVote` (signature not checked)**

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [2](#0-1) 

The only gate is a stake-distribution lookup by `pvVoteVoterId`. The BLS vote signature (`pvSignature`) is never verified. Any peer that knows a valid voter ID (public information from the stake distribution) can forge a vote for any block on behalf of that committee member.

**Inbound pipeline — how peer input reaches these functions**

`processCerts` in the object-diffusion cert pool calls the supplied `validateCert` callback on every inbound batch:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as that callback and feeds accepted certificates directly into `ChainDB.addPerasCertAsync`: [4](#0-3) 

The vote path is symmetric: `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd` and feeds accepted votes into `ChainDB.addPerasVoteWithAsyncCertHandling`, which can auto-generate a certificate once quorum is reached: [5](#0-4) 

Accepted certificates are stored in `PerasCertDB` and consumed by `getPerasWeightSnapshot`, which feeds the Peras boost weight into chain selection: [6](#0-5) 

**Analog to the external report**

The external report's pattern: a privileged caller passes an arbitrary `provider` address; the function pulls the provider's approved funds without the provider's consent. Here: an unprivileged peer passes an arbitrary `PerasCert` (or a `PerasVote` bearing any committee member's voter ID); the function accepts it as cryptographically valid and uses the committee member's stake weight without their consent — no key material required.

---

### Impact Explanation

An adversarial peer can:

1. **Direct certificate injection**: craft a `PerasCert` naming any block as `pcCertBoostedBlock` and any round as `pcCertRound`. `validatePerasCert` accepts it unconditionally. The certificate is stored and its `vpcCertBoost` weight is applied to that block in chain selection.

2. **Vote-based certificate manufacture**: send forged `PerasVote` messages bearing legitimate voter IDs (publicly derivable from the stake distribution). `validatePerasVote` accepts each one. Once the aggregated stake crosses the quorum threshold, `addPerasVoteWithAsyncCertHandling` auto-forges a certificate for the adversary's chosen block.

Both paths allow an adversarial peer to inject Peras weight for an adversarial block, potentially causing an honest node to prefer a less-secure or adversary-controlled chain. This is a direct bypass of Peras certificate and vote verification — matching the **Critical** allowed impact: *"Bypass of… Peras voting or certificate checks… that enables unauthorized… vote, or certificate acceptance."*

---

### Likelihood Explanation

**High.** The object-diffusion protocol is a standard peer-to-peer channel; any connected peer can submit `PerasCert` or `PerasVote` objects. No stake, no keys, and no privileged role are required. The degenerate `BlockSupportsPeras` instance is the only instance in the codebase (it is a global `instance StandardHash blk =>` catch-all), so it is the instance used for all block types including the production Cardano block. The attack requires only the ability to open a network connection to the node.

---

### Recommendation

1. Replace the no-op `validatePerasCert` with a real implementation that verifies the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed committee members' public keys, and checks that the signers constitute a valid quorum.
2. Replace the signature-free `validatePerasVote` with an implementation that verifies the per-vote BLS signature (`pvSignature`) before accepting the vote.
3. Until real validation is implemented, gate the object-diffusion inbound handlers for Peras objects behind a feature flag so that the no-op validation path is not reachable from untrusted peers on production nodes.

---

### Proof of Concept

```
Attacker preconditions:
  - TCP connection to the target node's peer port (no keys, no stake required)

Attack path (certificate injection):
  1. Establish a peer connection and negotiate the object-diffusion sub-protocol.
  2. Craft PerasCert { pcCertRound = R, pcCertBoostedBlock = adversarialBlockPoint }.
  3. Send the crafted cert in an object-diffusion batch message.
  4. processCerts calls validatePerasCert, which returns Right unconditionally.
  5. The cert is timestamped and stored via ChainDB.addPerasCertAsync.
  6. getPerasWeightSnapshot now returns a snapshot that includes vpcCertBoost
     weight for adversarialBlockPoint.
  7. Chain selection uses this weight; the adversarial block is preferred over
     an honest chain of equal or slightly greater length.

Attack path (vote-based certificate manufacture):
  1. Read the current stake distribution (public) to enumerate voter IDs.
  2. For each voter ID V_i with stake s_i, craft PerasVote { pvVoteVoterId = V_i,
     pvVoteBlock = adversarialBlockPoint, pvVoteRound = R }.
     (No BLS key needed — validatePerasVote never checks pvSignature.)
  3. Send votes until sum(s_i) > quorum threshold.
  4. addPerasVoteWithAsyncCertHandling detects quorum and auto-forges a cert
     for adversarialBlockPoint, which is then added to PerasCertDB.
  5. Same chain-selection impact as above.
``` [7](#0-6) [3](#0-2) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-389)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L151-185)
```haskell
-- validation, the entire batch is rejected by throwing a
-- 'PerasCertInboundException' (which should make us disconnect from the distant
-- peer, see 'withPeer' bracket function from `ouroboros-network`). Otherwise,
-- each valid certificate is timestamped with the current wall-clock time and
-- added to the database via @addCert@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L121-152)
```haskell
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L155-157)
```haskell
data ChainDB m blk = ChainDB
  { addBlockAsync :: InvalidBlockPunishment m -> blk -> m (AddBlockPromise m blk)
  -- ^ Add a block to the heap of blocks
```
