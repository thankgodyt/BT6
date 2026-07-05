### Title
`validatePerasCert` Unconditionally Accepts All Peras Certificates, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic validation. In contrast, the parallel `validatePerasVote` function performs a real check (stake-distribution membership). Any unprivileged peer can send a crafted `PerasCert` via the object-diffusion mini-protocol; it will pass "validation", be inserted into the ChainDB, and trigger chain selection with an attacker-chosen block receiving the full Peras weight boost — potentially causing the node to prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The `BlockSupportsPeras` instance (the only instance, used for all blocks) implements `validatePerasCert` as:

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

Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost. No committee membership, no cryptographic signature, no round-number plausibility check is performed.

**Contrast with `validatePerasVote` — which has a real check:**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`validatePerasVote` rejects a vote if the voter is not in the stake distribution. `validatePerasCert` has no equivalent gate.

**Inbound path — `processCerts` calls the stub and adds every cert:**

`makePerasCertPoolWriterFromChainDB` wires `validatePerasCert mkPerasParams` as the validation function passed to `processCerts`: [3](#0-2) 

`processCerts` calls `validateCert` on each inbound cert and adds all that return `Right` to the ChainDB: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every cert from every peer is added via `ChainDB.addPerasCertAsync`.

**Chain selection consequence:**

`addPerasCertAsync` enqueues the cert for the background chain-selection loop: [5](#0-4) 

The `PerasWeightSnapshot` derived from accepted certificates is used in `compareCandidateChains` inside `BlockFetchClientInterface`, giving the attacker-chosen block extra weight during chain comparison: [6](#0-5) 

**Exploit path (step-by-step):**

1. Attacker connects to an honest node as a normal peer.
2. Attacker sends a crafted `PerasCert` via the object-diffusion mini-protocol with `pcCertBoostedBlock` pointing to a block on an adversarial fork.
3. `processCerts` calls `validatePerasCert` → always `Right`.
4. Cert is inserted into the ChainDB with `vpcCertBoost = perasWeight params` (full boost).
5. Chain selection runs; the adversarial fork's tip now carries the full Peras weight boost.
6. If the adversarial fork is at least as long as the honest chain, the node switches to it.

### Impact Explanation

**High.** An unprivileged peer can inject arbitrary Peras certificates that are accepted without any cryptographic or committee-membership check. The injected certificate assigns the full Peras weight boost to an attacker-chosen block, directly influencing chain selection. This can cause an honest node to prefer a non-canonical or adversarially-controlled chain, violating the chain-selection security assumptions of the Peras protocol.

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is a standard peer-to-peer channel reachable by any connected peer. No special privileges, keys, or stake are required. The stub is the only implementation of `validatePerasCert` (it is the universal `instance StandardHash blk => BlockSupportsPeras blk`), so every production node is affected.

### Recommendation

Implement real cryptographic and semantic validation inside `validatePerasCert` before the Peras certificate diffusion path is active in production. At minimum, the implementation must verify:
- Committee membership of the certificate issuer(s).
- Cryptographic signatures over the certificate content.
- Round-number consistency with the current chain state.

Until real validation is in place, the object-diffusion endpoint for Peras certificates should be disabled or gated behind a feature flag that is off by default.

### Proof of Concept

```
Attacker peer → object-diffusion protocol
  → sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial block> }
  → processCerts calls validatePerasCert mkPerasParams cert
  → validatePerasCert returns Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })
  → ChainDB.addPerasCertAsync inserts cert
  → chain selection runs with adversarial block boosted by perasWeight
  → if adversarial fork length >= honest fork length, node switches chains
```

The stub at [7](#0-6)  guarantees the `Right` branch is always taken, making the `(errs, _) -> throw` branch in `processCerts` unreachable for certificates. [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L303-310)
```haskell
addPerasCertAsync ::
  forall m blk.
  IOLike m =>
  ChainDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  m (AddPerasCertPromise m)
addPerasCertAsync CDB{cdbTracer, cdbChainSelQueue} =
  addPerasCertToQueue (TraceAddPerasCertEvent >$< cdbTracer) cdbChainSelQueue
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
