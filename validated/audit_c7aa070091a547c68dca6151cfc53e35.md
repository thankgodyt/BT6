### Title
`validatePerasCert` Unconditionally Accepts Any Inbound Peras Certificate, Enabling Unprivileged Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production default instance of `validatePerasCert` in `SupportsPeras.hs` is a stub that unconditionally accepts every inbound `PerasCert` without performing any validation — no quorum check, no voter eligibility check, no signature verification. This stub is wired directly into the live certificate-diffusion ingest path (`processCerts` in `PerasCert.hs`). Any unprivileged peer can send a crafted `PerasCert` for an arbitrary block, have it accepted as a `ValidatedPerasCert` carrying the full configured `perasWeight` boost, and cause the receiving node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — unconditional acceptance in the default `BlockSupportsPeras` instance:** [1](#0-0) 

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

This is the **only** concrete `validatePerasCert` implementation in the codebase. It returns `Right` for every input, assigning the full `perasWeight params` boost to any certificate regardless of its content.

**Ingest path — `processCerts` calls this stub directly:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` (and its `PerasCertDB` sibling) both pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [3](#0-2) 

`processCerts` partitions the batch into valid/invalid using this callback and adds all "valid" certificates to the `ChainDB` or `PerasCertDB`: [4](#0-3) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable and every certificate in every batch is accepted.

**What a legitimate certificate must prove (but is never checked):**

The `votesReachQuorum` smart constructor — the only place `stakeAboveThreshold` is called — enforces that the total stake of the backing votes exceeds the quorum threshold before a certificate may be forged: [5](#0-4) 

This check is enforced locally when a node *forges* a certificate from its own vote aggregation state, but it is **never re-applied** when a certificate arrives from the network. The `validatePerasCert` stub bypasses it entirely.

**Analog to M-8:** In M-8, the liquidatee's USDC balance check could be satisfied by buying assets through a callback (indirect path) rather than the liquidator directly paying. Here, the certificate validity check — which should require a quorum of stake-weighted votes — can be satisfied by sending *any* `PerasCert` struct (the most indirect path possible: no quorum at all), because the check is completely absent.

---

### Impact Explanation

A `ValidatedPerasCert` carrying `vpcCertBoost = perasWeight params` is used by the ChainDB chain-selection logic to boost the weight of the certified block. An attacker who injects a certificate for a non-canonical block causes the receiving node to assign that block a higher chain weight, potentially making it prefer the adversarially chosen chain over the honest canonical chain. This is a **High** chain-selection integrity violation: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The attack requires only a network connection to a node that has Peras certificate diffusion enabled. No keys, no stake, no privileged access are needed. The attacker constructs a minimal `PerasCert` (two fields: `pcCertRound` and `pcCertBoostedBlock`) targeting any block point and sends it via the object-diffusion mini-protocol. The stub unconditionally accepts it.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate vote signature over the claimed voters.
2. Verifies each voter's eligibility against the epoch stake distribution (VRF outputs for non-persistent members, seat-index bounds for persistent members).
3. Recomputes the total vote weight from the verified eligibility witnesses and asserts `stakeAboveThreshold params totalWeight` — the quorum check that `votesReachQuorum` enforces locally but that is currently absent from the inbound validation path.

Until the real implementation is in place, the certificate-diffusion ingest path should reject all inbound certificates rather than accept them unconditionally.

---

### Proof of Concept

1. Connect to a node with Peras certificate diffusion active.
2. Construct a `PerasCert` with `pcCertRound = r` (any round) and `pcCertBoostedBlock = p` (the `Point` of any block, including a non-canonical one).
3. Send the certificate via the object-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert (perasWeight mkPerasParams))` unconditionally.
5. The certificate is stored in the `ChainDB` via `ChainDB.addPerasCertAsync`.
6. The ChainDB chain-selection logic applies the `perasWeight` boost to block `p`, causing the node to prefer the chain containing `p` over the honest canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-271)
```haskell
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
  allVotesMatchTarget target =
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
