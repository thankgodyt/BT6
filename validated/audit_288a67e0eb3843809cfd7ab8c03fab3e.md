### Title
Unconditional `validatePerasCert` stub accepts any peer-supplied Peras certificate without quorum or signature checks, enabling unauthorized chain-selection boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero quorum, signature, or voter-deduplication checks. Any unprivileged peer can craft a `PerasCert` for any round and any block point, send it over the Peras certificate miniprotocol, and have it accepted and applied as a valid boost to chain selection — without holding any stake or producing any valid votes.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for certificate acceptance: [1](#0-0) 

The only production instance — the catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as a no-op stub: [2](#0-1) 

Every certificate, regardless of its content, is wrapped in `Right ValidatedPerasCert` and returned. No checks are performed:
- No aggregate BLS signature verification
- No quorum threshold check (i.e., no check that enough stake-weighted votes back the certificate)
- No voter deduplication (the analog of the Solidity duplicate-delegate bug: a certificate embedding the same seat index multiple times would pass)
- No round-number or boosted-block plausibility check

This stub is the direct entry point for all inbound peer certificates. `processCerts` in the Peras certificate object pool calls it for every certificate received from a remote peer: [3](#0-2) [4](#0-3) 

`processCerts` partitions results into `(errors, validatedCerts)` and adds all `validatedCerts` to the ChainDB. Because `validatePerasCert` never returns `Left`, every certificate lands in the database.

The secondary data-validation analog — `votesReachQuorum` summing `vpvVoteStake` over a plain list without deduplicating by `PerasVoterId` — is also present: [5](#0-4) 

In the current internal call path (`updateCandidateVoteState` → `Map.elems ptvtVotes`) the `Map` key deduplicates voters before the list is passed in, so this path is not directly exploitable today. However, `votesReachQuorum` is exported and its contract does not enforce uniqueness, leaving a latent duplicate-voter inflation risk for any future caller.

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is added to the chain-selection weight of the boosted block: [6](#0-5) 

An attacker who can send a single crafted `PerasCert` (any `pcCertRound`, any `pcCertBoostedBlock`) will cause an honest node to prefer the attacker-chosen block over the honest canonical chain. Because `perasWeight` can be configured to be large (it is a `Word64` boost added directly to chain density), a single forged certificate can permanently redirect chain selection on the receiving node to a non-canonical or adversarially-chosen fork. This satisfies the **Critical** impact class: bypass of certificate verification enabling unauthorized certificate acceptance that directly corrupts chain selection.

---

### Likelihood Explanation

The attack requires only network access to a node running the Peras certificate miniprotocol. No stake, no keys, no cryptographic material is needed. The attacker constructs a CBOR-encoded `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, sends it as a valid miniprotocol message, and the node accepts it. The vulnerability is in the default production instance used for all block types until a concrete Cardano era overrides it. Likelihood is **High** for any deployment that activates the Peras certificate diffusion path.

---

### Recommendation

1. **Short term**: Replace the `validatePerasCert` stub with a real implementation that (a) verifies the aggregate BLS signature against the claimed voter set, (b) checks that the total stake-weighted vote count meets the quorum threshold, and (c) rejects certificates whose voter map contains duplicate seat indices. The existing `implVerifyCert` logic in `WFALS.hs` and `EveryoneVotes.hs` provides the correct pattern.

2. **Short term**: Add a deduplication guard in `votesReachQuorum` — either assert that all `pvVoteVoterId` values are distinct, or deduplicate the input list before summing stake — to close the latent duplicate-voter inflation path.

3. **Long term**: Add property-based tests that feed crafted/malformed certificates (wrong signature, insufficient quorum, duplicate voters) into `validatePerasCert` and assert they are rejected. The existing `prop_forgeCert_verifyCert` pattern in `WFALS/Tests.hs` and `EveryoneVotes/Tests.hs` is the right model.

---

### Proof of Concept

```
1. Attacker connects to a node via the Peras certificate miniprotocol.

2. Attacker serialises a minimal PerasCert:
     pcCertRound      = <any round number, e.g. 999>
     pcCertBoostedBlock = <hash of an adversarial or stale block>

3. Attacker sends the CBOR-encoded certificate as a valid miniprotocol message.

4. processCerts calls:
     validatePerasCert mkPerasParams cert
   which unconditionally returns:
     Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }

5. The certificate is added to the ChainDB via addPerasCertAsync.

6. Chain selection now applies vpcCertBoost to the adversarial block, causing the
   honest node to prefer it over the canonical chain — with no stake, no valid
   votes, and no cryptographic proof of quorum.
``` [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-272)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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
