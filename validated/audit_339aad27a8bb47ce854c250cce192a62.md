### Title
Peras Vote and Certificate Signature Verification Bypass Allows Any Peer to Forge Votes and Certificates, Manipulating Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance for `StandardHash blk` implements `validatePerasVote` with only a stake-distribution lookup (no cryptographic signature check) and implements `validatePerasCert` as an unconditional `Right` — accepting every certificate regardless of content. Any unprivileged peer reachable via the object-diffusion miniprotocol can therefore inject forged Peras votes claiming to be from any registered pool operator, accumulate a quorum, and trigger chain selection to boost an arbitrary block, or inject a forged certificate directly to achieve the same effect.

### Finding Description

**Root cause — `validatePerasVote` performs no signature verification** [1](#0-0) 

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

The only check is `lookupPerasVoteStake`: does the `pvVoteVoterId` field appear in the public stake distribution? No cryptographic proof that the sender controls that key is required. The `pvVoteVoterId` is a public `KeyHash` derivable from any registered pool's public key, which is on-chain data.

**Root cause — `validatePerasCert` is an unconditional accept** [2](#0-1) 

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

Every `PerasCert` received from any peer is unconditionally wrapped in `ValidatedPerasCert` and given the full `perasWeight` boost.

**Inbound path — `processVotes` and `processCerts` call these stubs directly**

Votes received over the network flow through `processVotes`: [3](#0-2) 

The `validateVote` callback passed in production is: [4](#0-3) 

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

Certificates flow through `processCerts`: [5](#0-4) 

Both functions reject the batch only if `validateVote`/`validateCert` returns `Left`. Since `validatePerasCert` never returns `Left`, and `validatePerasVote` returns `Left` only when the voter ID is absent from the public stake distribution, a peer that knows any registered pool's `KeyHash` (public on-chain data) can pass both checks.

**Downstream — accepted votes trigger automatic certificate forging and chain selection**

Once forged votes accumulate to quorum inside `implAddVote`, a `ValidatedPerasCert` is automatically forged: [6](#0-5) 

That certificate is then enqueued for chain selection via `addPerasCertAsync`: [7](#0-6) 

The `ValidatedPerasCert` carries a `vpcCertBoost` weight that directly influences which chain the node prefers: [8](#0-7) 

### Impact Explanation

**Severity: Critical / High (Peras voting/certificate check bypass + chain selection manipulation)**

An unprivileged peer can:

1. **Forge votes** for any block at any round by constructing `PerasVote` structs with any registered pool's `PerasVoterId`. Because `validatePerasVote` only checks the stake-distribution map, no private key is needed.
2. **Accumulate quorum** by sending enough forged votes (one per registered pool ID) to exceed the quorum threshold, causing the node to automatically forge a `ValidatedPerasCert` for an attacker-chosen block.
3. **Inject certificates directly** via the cert diffusion path, since `validatePerasCert` is unconditional.
4. **Manipulate chain selection**: the forged certificate gives the targeted block a `perasWeight` boost, potentially causing the honest node to prefer a non-canonical fork over the honest chain.

This maps directly to the allowed impact scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

- **Attacker preconditions**: none beyond a network connection. The `PerasVoterId` values (pool key hashes) are public on-chain data.
- **Protocol entry point**: the object-diffusion miniprotocol is open to any peer that can establish a connection.
- **No cryptographic barrier**: the stub explicitly skips signature verification (the TODO comment confirms this is known but unimplemented).
- **Likelihood: High** — any peer with knowledge of registered pool key hashes (trivially obtained from the chain) can execute this attack.

### Recommendation

1. **`validatePerasVote`**: implement cryptographic signature verification. The vote must carry a signature over `(electionId, candidate)` verifiable against the public key corresponding to `pvVoteVoterId`. The `Committee.WFALS` module already shows the correct pattern via `checkVoteSignature` / `verifyVoteSignature`. [9](#0-8) 

2. **`validatePerasCert`**: implement aggregate-signature verification. The `EveryoneVotes` and `WFALS` `implVerifyCert` implementations show the required pattern (verify aggregate BLS signature over `(electionId, candidate)` against the aggregated public keys of the claimed voters). [10](#0-9) 

3. Track the referenced issue (`https://github.com/tweag/cardano-peras/issues/120`) as a security-critical blocker before any deployment of the Peras object-diffusion path.

### Proof of Concept

**Forged-vote chain-selection manipulation (deterministic reasoning):**

1. Attacker node connects to victim via the object-diffusion miniprotocol.
2. Attacker reads the public stake distribution to enumerate registered `PerasVoterId` values (pool key hashes).
3. Attacker constructs `N` `PerasVote` structs — one per pool — all targeting an attacker-chosen block `B` at round `R`:
   ```
   PerasVote { pvVoteRound = R, pvVoteBlock = pointOf(B), pvVoteVoterId = poolKeyHash_i }
   ```
   No private key is required; the struct contains no signature field in the current degenerate instance.
4. Attacker sends the batch via `opwAddObjects` of the object-diffusion writer.
5. `processVotes` calls `validatePerasVote mkPerasParams sd vote` for each vote. Each passes because `lookupPerasVoteStake` finds the pool ID in the public distribution.
6. All votes are added to `PerasVoteDB` via `addPerasVoteWithAsyncCertHandling`.
7. `implAddVote` calls `updatePerasRoundVoteStates`; once total stake exceeds the quorum threshold, `VoteGeneratedNewCert cert` is returned and `addPerasCertAsync` is called.
8. Chain selection runs; block `B` receives `perasWeight` boost and may become the preferred chain tip, displacing the honest chain.

**Direct certificate injection (even simpler):**

1. Attacker constructs `PerasCert { pcCertRound = R, pcCertBoostedBlock = pointOf(B) }`.
2. Sends it via the cert diffusion path.
3. `processCerts` calls `validatePerasCert params cert` → unconditionally `Right`.
4. Certificate is added and triggers chain selection with full `perasWeight` boost for block `B`. [11](#0-10)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L139-148)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-189)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L338-350)
```haskell
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
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
