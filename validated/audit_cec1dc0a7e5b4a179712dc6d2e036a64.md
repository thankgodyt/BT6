### Title
Peras Certificate Validation Stub Always Accepts Any Certificate from Any Peer, Enabling Unauthorized Chain Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or authorization checks. Any unprivileged peer can inject arbitrary Peras certificates via the object-diffusion mini-protocol; each accepted certificate applies a chain-weight boost (`vpcCertBoost`) to an attacker-chosen block, directly influencing chain selection on the receiving node.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a certificate before it is stored and used for chain selection. The universal instance (the only production instance) implements it as:

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

No signature is verified, no committee membership is checked, no round-number bounds are enforced, and no issuer authorization is confirmed. The function is structurally identical to an unrestricted `mint()`: it accepts any input and stamps it as valid. [1](#0-0) 

**Attacker-controlled entry path — object diffusion mini-protocol:**

Inbound certificates arrive through `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the sole validation callback. Because the callback always returns `Right`, every certificate in every batch from every peer passes validation and is forwarded to `ChainDB.addPerasCertAsync`. [2](#0-1) 

The `processCerts` function itself is correctly structured — it calls `validateCert` and rejects batches containing failures — but the validation function it is given never produces a failure. [3](#0-2) 

**Chain selection impact — accepted certificates alter block weights:**

Once stored in `PerasCertDB`, each certificate contributes a `PerasWeight` boost to the block it names. The `getWeightSnapshot` path exposes these boosts to chain selection, causing the node to prefer the boosted chain over a longer but unboosted one. [4](#0-3) 

The `addPerasCertAsync` path in `ChainDB` explicitly triggers a fork switch if the boosted chain becomes weightier than the current selection. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block it chooses — including a minority fork or an adversarial chain — and send it to a target node. The node will accept it without question, apply the Peras weight boost to that block, and may switch its preferred chain to the attacker-chosen fork. This constitutes a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain**, matching the High impact tier. If the attacker can also supply the boosted blocks (or they already exist on a minority fork), the node permanently diverges from the honest majority chain.

---

### Likelihood Explanation

Any peer reachable via the object-diffusion mini-protocol can exploit this. No keys, stake, or special privileges are required. The attacker only needs to connect to the target node and send a well-formed CBOR-encoded `PerasCert` with a `pcCertBoostedBlock` pointing to the desired target. The Peras diffusion layer is active in the current codebase and the stub is the only production implementation.

---

### Recommendation

Implement real certificate validation inside `validatePerasCert`. At minimum this must include:

1. **Committee membership check** — verify that the certificate's aggregate signature was produced by a quorum of eligible committee members for the claimed round.
2. **Aggregate BLS signature verification** — use `verifyAggregateVoteSignature` (already implemented in `EveryoneVotes.implVerifyCert` and `WFALS.implVerifyCert`) against the certificate's claimed voters and the epoch nonce.
3. **Round-number bounds** — reject certificates whose round number is outside the valid window relative to the current chain tip.
4. **Boosted-block existence check** — reject certificates that name a block not present in the local VolatileDB or ImmutableDB.

The existing `implVerifyCert` implementations in `Ouroboros.Consensus.Committee.EveryoneVotes` and `Ouroboros.Consensus.Committee.WFALS` already contain the correct cryptographic logic and should be wired into `validatePerasCert` once the HFC plumbing (tracked in issue #73 / #120) is complete. Until that plumbing is in place, the diffusion of Peras certificates from untrusted peers should be disabled or gated behind a feature flag. [6](#0-5) 

---

### Proof of Concept

1. Connect to a target node that has the Peras object-diffusion mini-protocol enabled.
2. Craft a `PerasCert` with:
   - `pcCertRound` set to the current Peras round,
   - `pcCertBoostedBlock` set to the hash and slot of a minority-fork block that the attacker controls or has pre-seeded.
3. Send the certificate via the object-diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in `PerasCertDB` and its boost is reflected in `getWeightSnapshot`.
6. `addPerasCertAsync` triggers chain selection; if the boosted block's chain weight now exceeds the current selection, the node switches forks.

**Expected outcome:** The node adopts the attacker-chosen fork without any cryptographic proof that a legitimate quorum of committee members ever voted for it — the direct consensus analog of an unrestricted `mint()`.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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
