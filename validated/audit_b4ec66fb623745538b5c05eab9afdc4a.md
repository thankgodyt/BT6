### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Always Returning `Right` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default catch-all instance of `BlockSupportsPeras` ships a `validatePerasCert` implementation that unconditionally returns `Right` — accepting every inbound Peras certificate without performing any cryptographic or semantic check. Because this is the universal instance used for all block types (including production Cardano blocks, absent a more-specific override), any unprivileged peer can inject arbitrary Peras certificates through the object-diffusion mini-protocol. Those certificates are stored in the `PerasCertDB` and their weight boosts are applied during chain selection, allowing an attacker to steer an honest node toward a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras vote and certificate validation. Its default instance is declared as a catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
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

The function body is a single `Right` constructor — no signature check, no round-number bounds check, no committee-membership check, no quorum check. Every certificate presented by any peer is immediately wrapped in `ValidatedPerasCert` and returned as valid.

The inbound processing path in `processCerts` calls this function directly:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` partitions results into valid/invalid; because `validatePerasCert` never produces a `Left`, every certificate in every batch is accepted and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Accepted certificates are stored in the `PerasCertDB` and their weight boosts are read back as a `PerasWeightSnapshot` during chain selection: [4](#0-3) 

The snapshot is then passed to `preferAnchoredCandidate` and `compareAnchoredFragments`, which use the Peras boost to decide which candidate chain to adopt: [5](#0-4) 

The same stub also applies to `validatePerasVote`, which skips all cryptographic signature verification and only checks whether the claimed voter ID appears in the stake distribution: [6](#0-5) 

---

### Impact Explanation

An attacker who can send messages on the Peras object-diffusion mini-protocol (any network peer) can craft a `PerasCert` naming any block hash and any round number. Because `validatePerasCert` always returns `Right`, the certificate is stored and its weight boost is applied to that block during chain selection. The node will then prefer the boosted (potentially adversarial) chain over the honest canonical chain, constituting a chain-selection manipulation that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of Ouroboros Peras.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer. No special privileges, keys, or stake are required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message; the stub validation ensures it will always be accepted. The TODO comment and linked issue (`tweag/cardano-peras#120`) confirm this is a known incomplete implementation that has not yet been replaced with real validation.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) implementations with full cryptographic and semantic validation before the Peras object-diffusion protocol is enabled on any network where peers are untrusted. At minimum:

- Verify the aggregate BLS signature against the claimed voter set and election identifier (as `implVerifyCert` in `EveryoneVotes.hs` already demonstrates for the committee-based path).
- Enforce round-number bounds and committee-membership checks.
- Until real validation is in place, gate the object-diffusion endpoint so that inbound Peras certificates are not accepted from untrusted peers. [7](#0-6) 

---

### Proof of Concept

1. Connect to a node as a peer via the Peras certificate object-diffusion mini-protocol.
2. Construct a `PerasCert` (CBOR-encoded per `Serialise (PerasCert blk)`) with:
   - `pcCertRound` set to the current Peras round,
   - `pcCertBoostedBlock` set to the hash of any block on an adversarial fork.
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is added to `PerasCertDB` via `addPerasCertAsync`.
6. On the next chain-selection cycle, `getWeightSnapshot` returns a snapshot that includes the injected boost.
7. `preferAnchoredCandidate` now scores the adversarial fork higher than the honest chain; the node switches to it. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-372)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L174-182)
```haskell
    case NE.nonEmpty
      [ (chain, reason)
      | chain <- chains
      , ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
      ] of
      -- If there are no candidates, no chain selection is needed
      Nothing -> pure curChain
      Just chains' ->
        fromMaybe curChain <$> chainSelection' curChain chains'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L292-337)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
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
