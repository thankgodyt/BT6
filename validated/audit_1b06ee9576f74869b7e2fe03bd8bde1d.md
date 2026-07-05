### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Bypassing Quorum Authorization — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every inbound certificate, and `validatePerasVote` without verifying the cryptographic signature of the vote. These stubs are wired into the production code paths that process Peras certificates and votes received from unprivileged peers. An adversary can send crafted `PerasCert` objects that are accepted without any quorum or signature check, causing the node to apply an unearned chain-weight boost and potentially prefer a non-canonical chain.

---

### Finding Description

**Root cause — trivially weak "initial" validation parameters**

The external report's root cause is that an initial state is generated with `threshold = 0`, which makes `sss::share` return `secret = Fr::ZERO` — a deterministic, publicly derivable value that bypasses the guardian-approval invariant. The direct analog here is that the initial/default `BlockSupportsPeras` instance sets the effective validation threshold to zero by always returning `Right`:

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

Every `PerasCert` received from any peer is immediately wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost (default: 15 blocks) without checking:
- that the certificate was produced by a quorum of eligible voters,
- that the aggregate BLS signature is valid,
- that the round number is within the allowed window, or
- any other Peras protocol rule.

**Vote validation also skips signature verification**

`validatePerasVote` only checks that the claimed voter appears in the stake distribution; it never verifies the cryptographic signature on the vote:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [2](#0-1) 

An attacker who knows the public stake distribution (which is on-chain) can forge votes on behalf of any registered pool and accumulate enough stake to trigger `votesReachQuorum`, generating a fraudulent certificate entirely without the pools' private keys.

**These stubs are wired into the production inbound-certificate pipeline**

Both `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` call `validatePerasCert mkPerasParams` directly:

```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [3](#0-2) 

`processCerts` then adds every certificate that passes this no-op check to the ChainDB via `addPerasCertAsync`, which triggers chain selection: [4](#0-3) 

The `stakeAboveThreshold` guard inside `votesReachQuorum` does enforce a numeric threshold, but it is only reached after `validatePerasVote` has already accepted the forged votes: [5](#0-4) 

**Analogy to the external report**

| External report | This codebase |
|---|---|
| `threshold = 0` → `secret = Fr::ZERO` (deterministic) | `validatePerasCert → Right` always (no validation) |
| Initial social recovery state is publicly visible on-chain | Inbound certificate pipeline is reachable by any peer |
| Bypasses guardian-approval invariant | Bypasses Peras quorum-certificate invariant |
| `msk_ss_social` decryptable without guardian shares | Any `PerasCert` accepted without quorum proof |

The Peras security invariant that is violated is: *a certificate is only valid if it was produced by a quorum of eligible, cryptographically authenticated voters*. The stub makes this invariant vacuously satisfiable by any peer.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` for any block on any fork. The certificate is accepted without validation and stored in the ChainDB. Because accepted certificates apply a `perasWeight = 15` boost to the boosted block's chain, the node's chain-selection logic may switch to a non-canonical fork that carries the fraudulent boost. This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or adversarially chosen chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is part of the active node infrastructure. Any connected peer can send `PerasCert` objects. No stake, key material, or privileged access is required. The attacker only needs to know the on-chain stake distribution (public) to construct a vote set that passes the numeric `stakeAboveThreshold` check after the signature-free `validatePerasVote` accepts the forged votes.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature over the certificate's `(roundNo, boostedBlock)` payload against the committee's aggregate public key.
2. Replace the stub `validatePerasVote` with a real implementation that verifies the per-voter BLS signature before accepting the vote into the aggregation state.
3. Until real validation is in place, gate the Peras certificate inbound pipeline behind a feature flag so that it is not reachable from untrusted peers on production nodes.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate mini-protocol.
2. Observe the on-chain stake distribution to identify pools whose combined stake exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` (default: 77 %).
3. Construct `PerasVote` objects claiming to be from those pools for a target block on a minority fork, with arbitrary (invalid) signatures. Submit them via `addPerasVoteWithAsyncCertHandling`.
4. Because `validatePerasVote` does not check signatures, each vote is accepted and its stake is counted. Once the numeric threshold is crossed, `votesReachQuorum` returns `Just`, `forgePerasCert` produces a `ValidatedPerasCert`, and `addPerasCertAsync` inserts it into the ChainDB.
5. Alternatively, skip the vote path entirely: construct a `PerasCert` directly and send it via the Peras cert object-diffusion protocol. `validatePerasCert` returns `Right` unconditionally, and the certificate is added to the ChainDB with a 15-block weight boost.
6. The node's chain-selection logic now sees the minority fork as heavier and switches to it. [6](#0-5) [2](#0-1) [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L119-133)
```haskell
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
