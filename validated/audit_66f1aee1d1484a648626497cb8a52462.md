### Title
Peras Certificate and Vote Validation Unconditionally Accepts All Inbound Objects — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance — the only instance in the codebase — implements `validatePerasCert` as an unconditional `Right` and `validatePerasVote` without any cryptographic signature check. Any unprivileged peer connected via the Peras object-diffusion mini-protocol can send a crafted `PerasCert` or `PerasVote` that will be accepted and stored without any verification of committee membership, quorum, or BLS signature. Accepted certificates directly influence chain selection by boosting a block's weight; accepted votes accumulate toward quorum and trigger certificate forging. This is a complete bypass of Peras certificate and vote authorization.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:**

The sole `BlockSupportsPeras` instance, explicitly labelled a "degenerate instance for all blks to get things to compile", implements `validatePerasCert` as:

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

No field of the certificate is inspected. Any `PerasCert` — regardless of who sent it, what round it claims, or what block it claims to boost — is unconditionally promoted to a `ValidatedPerasCert` carrying a full `perasWeight` boost.

**Root cause — `validatePerasVote` skips signature verification:**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check is whether the claimed `PerasVoterId` appears in the stake distribution. No BLS signature over `(roundNo, boostedBlock)` is verified. An attacker who knows any registered stake pool's `KeyHash` (all of which are public on-chain) can forge votes for that pool.

**Inbound path — `processCerts` and `processVotes`:**

Both functions are wired directly to the peer-facing object-diffusion mini-protocol. `processCerts` calls the injected `validateCert` callback, which in the production wiring resolves to `validatePerasCert`:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
```

Because `validateCert` never returns `Left`, the `(errs, _)` branch is unreachable and every inbound certificate is stored.

**Chain-selection impact:**

A stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`. This boost is applied during chain selection to the block identified by `pcCertBoostedBlock`. An attacker can therefore make any block — including one on a minority or adversarial fork — appear heavier than the honest chain tip.

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote verification enabling unauthorized chain-selection manipulation.**

An unprivileged peer can:

1. **Forge a certificate for any block at any round** by sending a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` over the Peras cert mini-protocol. The certificate is accepted unconditionally and its boost is applied to block `p` during chain selection.

2. **Forge votes for any registered stake pool** by constructing `PerasVote { pvVoteVoterId = knownPoolId, ... }`. Because no BLS signature is checked, votes accumulate toward quorum using the real pool's stake weight, eventually triggering `forgePerasCert` locally and producing a locally-forged certificate for an attacker-chosen block.

Both paths allow an unprivileged peer to make an honest node prefer a non-canonical or adversarial chain, violating the Peras safety guarantee that only blocks with genuine quorum support receive a boost.

---

### Likelihood Explanation

**Likelihood: High** — given that Peras object diffusion is wired and active in the codebase. The attacker needs only a standard peer connection and knowledge of any registered stake pool's `KeyHash` (entirely public). No keys, no stake, no admin access are required. The attack is deterministic and requires no brute force.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate verification — verify that the certificate encodes a valid aggregate BLS signature over `(roundNo, boostedBlock)` from a set of committee members whose combined stake exceeds the quorum threshold. Remove the unconditional `Right` stub before Peras is enabled on any network.

2. **`validatePerasVote`**: Add BLS signature verification over `(roundNo, boostedBlock)` using the public key associated with `pvVoteVoterId`. Stake-distribution membership is a necessary but not sufficient condition.

3. **Guard the inbound path**: Until proper validation is implemented, the `processCerts` and `processVotes` handlers should reject all inbound objects (or the mini-protocol server should not be started) to prevent the stub from being reachable by peers.

---

### Proof of Concept

**Preconditions**: Attacker has a standard peer connection to a node with Peras object diffusion enabled. Attacker knows the `HeaderHash` of a target block `B` on a minority fork and any registered pool's `KeyHash` `K`.

**Steps**:

1. Attacker constructs `cert = PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B) }` for any round `r` not yet in the node's cert database.
2. Attacker sends `[cert]` via the Peras cert mini-protocol.
3. `processCerts` calls `validatePerasCert params cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is stored and its boost is applied to block `B` during the next chain selection.
5. If `perasWeight` is large enough, the node switches to the fork containing `B`.

**Vote-based variant**:

1. Attacker constructs `n` votes `PerasVote { pvVoteRound = r, pvVoteBlock = pointOf(B), pvVoteVoterId = K_i }` for distinct pool IDs `K_1 … K_n` whose combined stake exceeds quorum.
2. Attacker sends these votes via the Peras vote mini-protocol.
3. `processVotes` calls `validatePerasVote` for each; each passes because `lookupPerasVoteStake` finds `K_i` in the stake distribution.
4. Votes accumulate; `votesReachQuorum` triggers `forgePerasCert`, producing a locally-forged certificate for `B`.
5. Chain selection applies the boost to `B`.

**Expected outcome**: The honest node adopts the attacker-chosen fork without any genuine quorum having been reached.

---

**Key file references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-200)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
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
