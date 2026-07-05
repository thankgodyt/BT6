### Title
`validatePerasCert` Unconditionally Accepts All Peras Certificates Without Any Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance, which applies to all block types including Cardano blocks, implements `validatePerasCert` as an unconditional `Right` — accepting every certificate received from any peer without performing any cryptographic, structural, or quorum check. Analogously, `validatePerasVote` only checks stake-distribution membership and skips signature verification entirely. An unprivileged peer can inject arbitrary Peras certificates and forged votes via the object-diffusion miniprotocol, causing honest nodes to store fraudulent certificates that boost attacker-chosen blocks in chain selection.

### Finding Description

The `BlockSupportsPeras` typeclass defines the interface for Peras vote and certificate validation. A catch-all instance is provided for all `StandardHash blk` types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

Within this instance, `validatePerasCert` performs **zero checks** and unconditionally returns `Right`:

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

`validatePerasVote` only checks whether the voter ID appears in the stake distribution, but never verifies a cryptographic signature (the stub `PerasVote` data type carries no signature field at all):

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [2](#0-1) 

The stub `PerasCert` and `PerasVote` data types carry no signature fields: [3](#0-2) 

These validators are invoked directly from the network-facing object-diffusion layer. `processCerts` calls the passed `validateCert` function on every inbound certificate batch from a peer: [4](#0-3) 

`processVotes` similarly calls `validatePerasVote` (via `makePerasVotePoolWriterFromChainDB`) on every inbound vote batch: [5](#0-4) 

The contrast with the real committee implementations (`WFALS`, `EveryoneVotes`) is stark — those verify cryptographic signatures, VRF outputs, seat-index bounds, and stake positivity before accepting any vote or certificate: [6](#0-5) 

The degenerate instance is the one actually compiled into nodes because no Cardano-era-specific override exists yet.

### Impact Explanation

A Peras certificate carries a `vpcCertBoost` weight that is applied to the certified block's chain during chain selection. By injecting a fraudulent `PerasCert` pointing to an attacker-controlled block, an adversary causes honest nodes to assign extra weight to a non-canonical chain. If the boost exceeds the honest chain's natural weight advantage, the node will switch to the attacker's chain — a direct chain-selection safety failure.

For votes: because `validatePerasVote` never checks a signature, an attacker can forge votes for any pool ID visible in the public stake distribution. By forging enough high-stake pool votes to satisfy `votesReachQuorum`, the attacker triggers local certificate forging (`forgePerasCert`) for an arbitrary block, compounding the chain-selection impact.

**Impact category:** High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.

### Likelihood Explanation

The object-diffusion miniprotocol is reachable by any peer that can establish a standard node-to-node connection. No privileged access, leaked keys, or stake majority is required. The attacker only needs to know a pool ID present in the public stake distribution (trivially observable on-chain) and craft a minimal `PerasCert` or `PerasVote` CBOR message. The degenerate instance is the only compiled instance for Cardano blocks.

### Recommendation

1. **Immediate:** Gate `processCerts` and `processVotes` so that the degenerate instance's `validatePerasCert`/`validatePerasVote` always returns `Left` (reject all) until a real implementation is in place, rather than `Right` (accept all). This prevents the network-facing path from accepting any certificate or vote until proper validation exists.

2. **Structural:** Add a signature field to the stub `PerasCert` and `PerasVote` data types and implement cryptographic verification (matching the pattern in `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyVote`) before enabling Peras on any production network.

3. **Quorum check in `validatePerasCert`:** Even before full crypto is wired in, `validatePerasCert` must at minimum verify that the certificate's round number is within the current Peras window and that the boosted block point is on the node's known chain.

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  object-diffusion miniprotocol (node-to-node)
  │  sends: PerasCert { pcCertRound = R, pcCertBoostedBlock = <attacker block> }
  ▼
processCerts
  └─ validateCert cert
       └─ validatePerasCert params cert          -- default instance
            └─ Right ValidatedPerasCert          -- NO checks performed
                 { vpcCert = cert
                 , vpcCertBoost = perasWeight params }
  └─ addCert (WithArrivalTime now validatedCert)
       └─ stored in PerasCertDB

Chain selection reads PerasCertDB
  └─ applies vpcCertBoost to <attacker block>'s chain weight
  └─ honest node switches to attacker's chain
```

For votes, the attacker additionally:
1. Reads the public stake distribution to enumerate pool IDs.
2. Sends `PerasVote { pvVoteRound = R, pvVoteBlock = <attacker block>, pvVoteVoterId = <high-stake pool> }` for enough pools to satisfy `stakeAboveThreshold`.
3. `validatePerasVote` accepts each vote (stake-distribution lookup succeeds, no signature checked).
4. `votesReachQuorum` returns `Just`, triggering `forgePerasCert` locally for the attacker's block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-336)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L494-518)
```haskell
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    -- 3. optionally, their VRF verification keys and outputs (to verify the
    --    aggregate VRF output for non-persistent voters, if any)
    (members, voteVerificationKeys, optionalVRFKeysAndOutputs) <-
      fmap nonEmptyUnzip3 . flip traverse (NEMap.toAscList voters) $ \case
        -- Persistent voter
        (seatIndex, Nothing)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , isPersistentMember seatIndex committee -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              pure
                ( WFALSPersistentMember
                    seatIndex
                    voterStake
                , voterVoteVerificationKey
                , Nothing
                )
          | otherwise ->
              Left (NotAPersistentMember seatIndex)
```
