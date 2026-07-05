### Title
`validatePerasCert` Unconditionally Accepts Any Crafted Certificate Without Validation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that always returns `Right` — performing zero checks on the certificate's round number, boosted-block point, quorum proof, or any cryptographic material. Any certificate received from an unprivileged peer over the Peras object-diffusion mini-protocol is unconditionally accepted, stored in `PerasCertDB`, and its boost weight is applied to chain selection. This is a direct bypass of Peras certificate authorization.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the default `BlockSupportsPeras` instance (which applies to every `StandardHash blk`) implements `validatePerasCert` as an unconditional stub:

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

This stub is the validation function wired directly into the inbound certificate pipeline. In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, `processCerts` calls it for every certificate received from a peer:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then passes every "validated" certificate to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Once in `PerasCertDB`, the certificate's `vpcCertBoost` weight is consumed by `preferAnchoredCandidate` during chain selection. The `ValidatedPerasCert` wrapper is the type-level proof that a certificate passed validation — but here that proof is forged unconditionally.

The checks that are entirely absent:
1. **Round-number validity** — the certificate's `pcCertRound` is never checked against the current Peras round or any cooldown state.
2. **Boosted-block existence** — `pcCertBoostedBlock` is never verified to exist on any known chain fragment.
3. **Quorum proof** — there is no check that the certificate was produced from a quorum of valid votes (the `forgePerasCert` path via `votesReachQuorum` is bypassed entirely for inbound certs).
4. **Cryptographic signature** — no signature over the certificate content is verified.

By contrast, `validatePerasVote` at least checks stake-distribution membership before accepting a vote: [4](#0-3) 

`validatePerasCert` performs no analogous check whatsoever.

The `BlockSupportsPeras` class contract requires `validatePerasCert` to return `Left` for invalid certificates: [5](#0-4) 

The stub violates this contract for every possible invalid input.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for any `Point blk` — including a point on a minority or adversarial fork — and send it over the Peras object-diffusion mini-protocol. The certificate will be accepted without any check, stored in `PerasCertDB`, and its `vpcCertBoost` weight will be applied in `preferAnchoredCandidate` during chain selection. Because Peras boost weight can tip the chain-selection tiebreaker, an adversary with no stake can cause honest nodes to prefer a non-canonical chain, directly undermining the Peras safety guarantee. This is a bypass of Peras certificate authorization: the `ValidatedPerasCert` type is supposed to be an unforgeable proof of quorum, but the stub manufactures it for any input.

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol and `PerasCertDB` pipeline are wired into the node's diffusion layer and are active whenever Peras is enabled (including private testnets and any future mainnet deployment). The attack requires only a TCP connection to a Peras-enabled node and the ability to send a single well-formed `PerasCert` message — no stake, no keys, no prior chain knowledge. The entry path is fully unprivileged and reachable from any peer.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that, at minimum:

1. Verifies the certificate's `pcCertRound` is consistent with the current Peras round state.
2. Verifies `pcCertBoostedBlock` refers to a block that exists on a known chain fragment.
3. Verifies the certificate was produced from a quorum of valid, stake-weighted votes (i.e., re-runs the `votesReachQuorum` check against the votes that produced it, or verifies an aggregated proof).
4. Verifies any cryptographic signature over the certificate content.

Until a real implementation is available, the stub should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the type-level `ValidatedPerasCert` invariant is not silently violated.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node's Peras object-diffusion endpoint.
2. Construct a `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialPoint }` for any desired block point, including one on a minority fork.
3. Send the certificate via the mini-protocol.
4. `processCerts` calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is stored in `PerasCertDB` and its boost weight is applied in the next chain-selection run via `preferAnchoredCandidate`, causing the node to prefer the adversarially boosted chain. [6](#0-5) [7](#0-6)

### Citations

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
