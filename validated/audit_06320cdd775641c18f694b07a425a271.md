### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic and Semantic Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional stub that accepts every inbound certificate without performing any cryptographic or semantic check. The inbound certificate processing pipeline (`processCerts`) in the Peras mini-protocol calls this stub directly on peer-supplied data. An unprivileged peer can therefore inject arbitrary `PerasCert` values — with any round number and any boosted-block pointer — into the node's `PerasCertDB` and `ChainDB`, causing those certificates to influence chain selection.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for all inbound certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only instance in the codebase is a universal catch-all (`instance StandardHash blk => BlockSupportsPeras blk`), explicitly labelled a "degenerate instance … to get things to compile". Its body unconditionally returns `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

No more-specific instance overrides this for any concrete block type; the stub is therefore the live implementation for all block types, including Cardano mainnet blocks.

**Attacker-controlled entry path — `processCerts` in the Peras cert mini-protocol**

`makePerasCertPoolWriterFromChainDB` (the production writer used when Peras is active) passes `validatePerasCert mkPerasParams` directly as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← stub, always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every peer-supplied certificate and, if all return `Right`, timestamps and stores them:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never returns `Left`, the `errs` branch is unreachable. Every certificate a peer sends is stored.

**Chain-selection consequence**

Stored certificates are fed into `addPerasCert` → `chainSelection`. A certificate boosts the chain weight of its `pcCertBoostedBlock` by `vpcCertBoost`. An attacker who injects a certificate pointing to an arbitrary block can therefore make the node assign inflated weight to that block and prefer a non-canonical fork. [4](#0-3) 

**Analogous gap in `validatePerasVote`**

The same universal instance implements `validatePerasVote` with only a stake-distribution lookup and no signature check:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [5](#0-4) 

An attacker who knows any legitimate voter ID (publicly visible in the stake distribution) can forge votes for that voter without possessing their BLS private key. The `processVotes` pipeline accepts these forged votes through the same pattern. [6](#0-5) 

The cryptographic machinery that *would* perform the check (`verifyVoteSignature`, `verifyAggregateVoteSignature`, `implVerifyCert`) exists in the `WFALS` and `EveryoneVotes` committee implementations but is never wired into the `BlockSupportsPeras` instance used by the production pipeline. [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance and chain-selection manipulation.**

Any unprivileged peer connected via the Peras object-diffusion mini-protocol can:

1. Craft a `PerasCert` with `pcCertRound = r` and `pcCertBoostedBlock = p` for any round `r` and any block point `p`.
2. Send it to a victim node. `processCerts` calls `validatePerasCert`, receives `Right`, and stores the certificate.
3. The stored certificate is passed to `addPerasCert` → `chainSelection`, where it inflates the chain weight of block `p` by `perasWeight params`.
4. If `p` is on a non-canonical fork, the victim node may switch to that fork, diverging from the honest chain.

For votes: an attacker who knows any legitimate `PerasVoterId` can forge votes for that voter, accumulate fake quorum, and cause the node to forge a certificate for an attacker-chosen block — all without holding any cryptographic key.

---

### Likelihood Explanation

**High.** The entry path is a standard peer-to-peer mini-protocol message handler. No privileged access, no key material, and no stake are required. The attacker only needs a TCP connection to the node and knowledge of the Peras wire format (which is public). The stub is the only instance; there is no fallback or defence-in-depth check downstream of `validatePerasCert` before the certificate reaches chain selection.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a call to the existing `implVerifyCert` (or equivalent) from the `WFALS`/`EveryoneVotes` committee implementations. At minimum, the check must:

1. Verify that `pcCertRound` corresponds to a valid, expected election round derived from the current ledger state.
2. Verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the public keys of the claimed voters.
3. Verify that the claimed voters constitute a quorum under the current stake distribution.

Similarly, `validatePerasVote` must call `verifyVoteSignature` before accepting a vote.

The existing `verifyCert` / `verifyVote` abstractions in `Ouroboros.Consensus.Committee.Class` already provide the correct interface; the missing step is wiring them into the `BlockSupportsPeras` instance used by the production pipeline.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Attacker connects to a victim node via the Peras cert object-diffusion mini-protocol.
2. Attacker sends a batch containing one `PerasCert`:
   - `pcCertRound = 999` (a future round)
   - `pcCertBoostedBlock = <hash of attacker-controlled fork tip>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}`.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. `addPerasCert` → `chainSelection` runs; the attacker's fork tip now carries the full Peras boost weight.
6. If the attacker's fork is otherwise competitive (e.g., equal block count), the victim node switches to it, diverging from the honest chain. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L460-474)
```haskell
addPerasCert ::
  forall blk.
  (LedgerSupportsProtocol blk, LedgerTablesAreTrivial ExtLedgerState blk) =>
  TopLevelConfig blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  Model blk ->
  (AddPerasCertChainSelOutcome, Model blk)
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
 where
  secParam = configSecurityParam cfg
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L494-562)
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
        -- Non-persistent voter
        (seatIndex, Just vrfOutput)
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
          , not (isPersistentMember seatIndex committee) -> do
              let voterVoteVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              let voterVRFVerificationKey =
                    getVRFVerificationKey (Proxy @crypto) voterPublicKey
              let numSeats =
                    localSortitionNumSeats
                      (nonPersistentCommitteeSize committee)
                      (totalNonPersistentStake committee)
                      voterStake
                      (normalizeVRFOutput vrfOutput)
              case nonZero numSeats of
                Nothing ->
                  Left (ZeroNonPersistentSeats seatIndex)
                Just nonZeroNumSeats ->
                  pure
                    ( WFALSNonPersistentMember
                        seatIndex
                        voterStake
                        vrfOutput
                        nonZeroNumSeats
                    , voterVoteVerificationKey
                    , Just (voterVRFVerificationKey, vrfOutput)
                    )
          | otherwise ->
              Left (NotANonPersistentMember seatIndex)

    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
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
