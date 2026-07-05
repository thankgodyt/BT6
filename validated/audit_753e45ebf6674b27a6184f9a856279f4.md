### Title
Peras Certificate and Vote Validation Stubs Unconditionally Accept Any Peer-Supplied Object, Bypassing Cryptographic Authorization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance ships two stub validators — `validatePerasCert` and `validatePerasVote` — that are reachable from the live object-diffusion inbound path. `validatePerasCert` unconditionally returns `Right` for every certificate a peer sends, performing zero cryptographic checks. `validatePerasVote` checks only that the voter ID exists in the stake distribution map but never verifies the vote signature. An unprivileged peer can therefore inject arbitrary Peras certificates and forged votes that pass validation, are stored in the local `CertDB`/`VoteDB`, and feed directly into chain-selection weight computation.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

Every certificate, regardless of its cryptographic content, is wrapped in `Right ValidatedPerasCert` and assigned the full `perasWeight`. No signature, no committee membership, no round/slot bounds are checked.

**Root cause — `validatePerasVote` stub:** [2](#0-1) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only gate is a `Map.lookup` on the voter ID. The vote signature is never verified. Any peer that knows a registered pool's `KeyHash` can forge a vote attributed to that pool.

**Inbound path — `processCerts`:** [3](#0-2) 

`processCerts` calls the injected `validateCert` callback on every inbound certificate. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would throw `PerasCertValidationError` is never taken; every certificate is timestamped and forwarded to `addCert`.

**Inbound path — `processVotes`:** [4](#0-3) 

`processVotes` follows the same pattern: the `validateVote` callback is `validatePerasVote`, which passes any vote whose voter ID appears in the current stake distribution.

**Chain-selection consequence:**

Accepted `ValidatedPerasCert` objects are stored in `CertDB` and read back by `getPerasWeightSnapshot` to build the `PerasWeightSnapshot` used in `compareCandidateChains`. [5](#0-4) 

A peer that injects a certificate boosting its own adversarial block causes the local node to assign that block a higher `PerasWeight`, making it preferred over the honest chain in chain selection.

**Exploit flow:**

1. Attacker connects as an ordinary peer (no keys required).
2. Attacker sends a crafted `PerasCert` via the object-diffusion mini-protocol, naming any block hash as the boosted block.
3. `processCerts` calls `validatePerasCert`; stub returns `Right`; cert is stored in `CertDB`.
4. `getPerasWeightSnapshot` returns a snapshot that includes the injected boost.
5. `compareCandidateChains` now prefers the attacker's chain fragment over the honest chain.
6. The node downloads and attempts to adopt the adversarial chain.

For votes: the attacker forges votes attributed to real stake pools (whose `KeyHash` values are public on-chain), accumulates enough forged stake to trigger `votesReachQuorum`, and causes the node to forge a certificate for an adversarial block internally. [6](#0-5) 

---

### Impact Explanation

**Severity: Critical / High.**

- **Certificate injection** bypasses the entire Peras certificate authorization check. The attacker gains unilateral ability to assign the full `perasWeight` boost to any block of their choosing, directly manipulating chain selection. This is a bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance — matching the "Critical" and "High" allowed impact categories.
- **Vote forgery** allows an attacker who knows any registered pool's `KeyHash` (public information) to cast votes on behalf of that pool without possessing its signing key. Accumulating enough forged votes triggers internal certificate forging for an adversarial block.
- Both attacks require only a standard peer connection; no privileged keys, no stake, no admin access.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is reachable from any peer connection. The attacker needs only:
- A standard node-to-node connection (no authentication beyond the normal handshake).
- Knowledge of registered pool `KeyHash` values (publicly available from the ledger state).
- The ability to serialize a valid-looking `PerasCert` or `PerasVote` CBOR structure.

The stubs are in the production library path (`ouroboros-consensus/src/ouroboros-consensus/`), not in test libraries. The TODO comments reference a tracked issue (`tweag/cardano-peras#120`), confirming the incomplete validation is a known gap in the shipped code, not an intentional design choice.

---

### Recommendation

1. **`validatePerasCert`**: Implement full cryptographic verification — check the aggregate BLS signature against the declared committee members, verify each member's committee eligibility and seat index, and enforce round/slot bounds before returning `Right`.

2. **`validatePerasVote`**: Add vote-signature verification using the voter's registered BLS verification key before accepting the vote. The `checkVoteSignature` helper already exists in `WFALS.hs` and should be called here. [7](#0-6) 

3. Until full validation is implemented, gate the object-diffusion inbound handlers with a feature flag that rejects all Peras objects when the validation stubs are active, preventing the unauthenticated acceptance path from being reachable on any live network.

---

### Proof of Concept

**Certificate injection (no keys required):**

```
1. Connect to target node as a peer (standard NtN handshake).
2. Craft a PerasCert CBOR payload:
     { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block hash> }
3. Send via the object-diffusion mini-protocol (MsgObjects [craftedCert]).
4. processCerts calls validatePerasCert → returns Right unconditionally.
5. Cert is stored in CertDB with full perasWeight boost.
6. Node's chain selection now prefers the adversarial block.
```

**Vote forgery (voter ID from public ledger):**

```
1. Query the ledger for any registered stake pool KeyHash (e.g., via GetStakeDistribution).
2. Craft a PerasVote:
     { pvVoteRound = R, pvVoteBlock = <adversarial block>, pvVoteVoterId = <known KeyHash> }
   (signature field is present in the struct but never checked by validatePerasVote)
3. Send N such votes (for N distinct pool KeyHashes) until votesReachQuorum returns Just.
4. Node internally forges a ValidatedPerasCert for the adversarial block.
5. Chain selection is manipulated as above.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L237-270)
```haskell
-- | Smart constructor for 'ValidatedPerasVotesReachingQuorum'.
--
-- This function checks that all votes are for the same target, and that their
-- total stake is above the quorum threshold defined in the given 'PerasCfg'.
-- It returns 'Nothing' if either of these conditions is not met.
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-200)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-241)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
          }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L600-600)
```haskell
checkVoteSignature ::
```
