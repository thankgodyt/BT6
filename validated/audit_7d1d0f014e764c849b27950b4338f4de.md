### Title
`validatePerasCert` stub unconditionally accepts all inbound Peras certificates without cryptographic or semantic validation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole deployed `BlockSupportsPeras` instance's `validatePerasCert` is a stub that always returns `Right`, accepting every inbound `PerasCert` without any cryptographic or semantic check. This stub is wired directly into the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject arbitrary Peras certificates into the `PerasCertDB`, bypassing all validation, and cause those certificates to influence chain selection and voting rules.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate that must approve every inbound `PerasCert` before it is stored. The only deployed instance is the catch-all default in `SupportsPeras.hs`:

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

This stub unconditionally wraps every certificate in `Right`, meaning it never rejects any certificate regardless of its content — no signature check, no round-number bounds check, no block-existence check.

This stub is wired directly into the production inbound-certificate processing path in `makePerasCertPoolWriterFromChainDB`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` only filters out certificates whose round number is already present in the DB (`alreadyInDb`). For all other certificates it calls `validateCert` — which is `validatePerasCert mkPerasParams` — and, since it always returns `Right`, immediately adds them to the `ChainDB` via `ChainDB.addPerasCertAsync`: [3](#0-2) 

The structural parallel to the external report is exact:

| External report | This codebase |
|---|---|
| `checkShortMinErc()` checks `shortRecordId` and `addr` but **not** `orderType == O.Cancelled`, so a cancelled order passes validation | `processCerts` calls `validatePerasCert` which checks **nothing** (always `Right`), so any crafted certificate passes validation |

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` (pointing to any block, including one on a non-canonical fork). Since `validatePerasCert` always returns `Right`, `processCerts` accepts the certificate and adds it to the `ChainDB` via `ChainDB.addPerasCertAsync`, triggering chain-selection side-effects. [4](#0-3) 

Additionally, the injected certificate becomes the `latestCertSeen` in `PerasVotingView`, which directly controls the Peras voting rules VR-1A, VR-1B, VR-2A, and VR-2B: [5](#0-4) 

A malicious peer can therefore:

1. **Force the node to vote for a non-canonical block** — by injecting a certificate whose `pcCertBoostedBlock` points to a fork block, causing VR-1B (`lcsCandidateBlockExtendsCert`) to pass only for that fork.
2. **Suppress the node's votes entirely** — by injecting a certificate for a future round, causing VR-1A (`currRoundNo :==: getPerasCertRound cert + 1`) to fail for the current round.
3. **Manipulate cooldown entry/exit** — by injecting a certificate that satisfies or violates VR-2A/VR-2B round-number arithmetic, forcing the node into or out of a cooldown period.
4. **Skew chain selection** — the injected `vpcCertBoost` weight is applied to the certified block during chain selection, potentially making a weaker fork appear heavier.

This matches two allowed impact categories:
- **Critical**: bypass of Peras certificate/signature validation enabling unauthorized certificate acceptance.
- **High**: chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The attacker-controlled entry path is the Peras certificate diffusion mini-protocol (`ObjectDiffusion`), reachable by any unprivileged peer. The peer sends a batch of crafted `PerasCert` objects. `processCerts` accepts them without any cryptographic or semantic validation. No special privileges, keys, or stake are required — only a network connection to the target node. [6](#0-5) 

---

### Recommendation

Replace the stub `validatePerasCert` with an implementation that:

1. Verifies the aggregate BLS/committee signature over the certificate's `(electionId, candidate)` pair against the committee's aggregate verification key for the claimed round.
2. Checks that `pcCertRound` is within the valid range (not in the future, not older than the expiry window `_A`).
3. Checks that `pcCertBoostedBlock` is a known block on the node's chain.

The fix should be applied before the Peras certificate diffusion mini-protocol is enabled in production. The existing `verifyCert` logic in the `VotingCommittee` abstraction (e.g., `implVerifyCert` in `WFALS.hs`) provides the correct cryptographic template: [7](#0-6) 

---

### Proof of Concept

A malicious peer connected via the Peras certificate diffusion mini-protocol sends a single crafted certificate:

```haskell
craftedCert = PerasCert
  { pcCertRound    = currentRound + 1   -- future round, not yet voted on
  , pcCertBoostedBlock = someNonCanonicalForkPoint
  }
```

`processCerts` calls `validatePerasCert mkPerasParams craftedCert`, which returns:

```haskell
Right ValidatedPerasCert
  { vpcCert   = craftedCert
  , vpcCertBoost = perasWeight mkPerasParams
  }
```

The certificate is added to the `ChainDB` via `ChainDB.addPerasCertAsync`. The node's `latestCertSeen` is now `craftedCert` (round `currentRound + 1`). On the next voting opportunity, VR-1A evaluates `currRoundNo :==: (currentRound + 1) + 1`, which fails, suppressing the node's vote. Simultaneously, the `vpcCertBoost` weight is applied to `someNonCanonicalForkPoint` during chain selection, potentially causing the node to switch to the attacker's fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L127-165)
```haskell
-- | VR-1A: the voter has seen the certificate for the previous round, and the
-- certificate was received in the first X slots after the start of the round.
perasVR1A ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR1A
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
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
