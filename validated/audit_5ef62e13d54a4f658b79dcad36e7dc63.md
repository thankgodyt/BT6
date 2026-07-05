### Title
Peras Certificate and Vote Validation Bypass via Stub `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal degenerate `BlockSupportsPeras` instance used in production inbound-processing pipelines implements `validatePerasCert` as an unconditional `Right` (always-accept) and `validatePerasVote` without any cryptographic signature check. Both functions are wired directly into the peer-facing certificate and vote ingest paths (`makePerasCertPoolWriterFromChainDB`, `makePerasVotePoolWriterFromChainDB`). An unprivileged peer can therefore inject arbitrary Peras certificates or impersonate any registered stake pool voter with no key material, bypassing all cryptographic authorization checks.

### Finding Description

**Root cause — `validatePerasCert` is an unconditional stub:** [1](#0-0) 

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

Every `PerasCert` received from a peer is unconditionally wrapped in `Right` and returned as `ValidatedPerasCert`. No quorum proof, no aggregate BLS signature, no voter eligibility check, no election-ID binding is performed.

**Root cause — `validatePerasVote` carries no signature field and performs no cryptographic check:**

The degenerate `PerasVote blk` data type contains only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — no cryptographic signature field exists: [2](#0-1) 

`validatePerasVote` therefore only checks stake-distribution membership; it cannot and does not verify that the claimed voter actually signed the vote: [3](#0-2) 

**Production entry path — both stubs are wired into the peer ingest pipeline:**

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` (the stub) for every certificate batch received from a peer: [4](#0-3) 

`makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` (the stub) for every vote batch received from a peer: [5](#0-4) 

`processCerts` and `processVotes` treat a `Right` result as proof of validity and immediately persist the object: [6](#0-5) 

The degenerate instance is the **only** `BlockSupportsPeras` instance in the codebase (it is a universal `instance StandardHash blk => BlockSupportsPeras blk`), so no more-specific production instance overrides it: [7](#0-6) 

**Analogy to the reported vulnerability:** Just as `isValidProxySignature` accepted any authority chain of length 1 without verifying that `authority[0]` was actually the proxy owner, `validatePerasCert` accepts any certificate without verifying the aggregate BLS signature or quorum, and `validatePerasVote` accepts any vote without verifying the voter's cryptographic signature.

### Impact Explanation

**Severity: Critical — bypass of Peras certificate/vote authorization.**

1. **Forged certificate injection:** Any unprivileged peer can craft a `PerasCert` naming any `pcCertRound` and any `pcCertBoostedBlock` (including an adversarial block). `validatePerasCert` returns `Right` unconditionally. The certificate is stored in `PerasCertDB` / `ChainDB` and applied to chain selection, granting the adversarial block an unearned Peras weight boost. This can cause honest nodes to prefer a non-canonical chain, constituting a chain-selection safety failure.

2. **Vote impersonation:** Any unprivileged peer can send a `PerasVote` claiming to be any `PerasVoterId` present in the stake distribution. `validatePerasVote` accepts it as long as the voter ID exists in the distribution. Enough such forged votes can trigger quorum and cause `forgePerasCert` to produce a certificate for an adversarial block, again corrupting chain selection.

### Likelihood Explanation

The attack requires only network access to a node running with Peras enabled. No keys, no stake, no privileged position is needed. The attacker simply sends a well-formed CBOR-encoded `PerasCert` or `PerasVote` over the Peras object-diffusion mini-protocol. The inbound handler (`processCerts` / `processVotes`) will call the stub validator, receive `Right`, and persist the object. Likelihood is **High** once Peras is activated on any network where this code is deployed.

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the aggregate BLS signature over the claimed voters and election ID, checks quorum against the stake distribution, and validates the boosted block's existence and era.
2. Extend the `PerasVote blk` data type (or the `BlockSupportsPeras` class interface) to carry a cryptographic signature field, and implement `validatePerasVote` to verify that signature against the claimed voter's public key from the stake distribution.
3. Until a real implementation is ready, the inbound handlers should reject all Peras objects rather than accept them unconditionally, to prevent the stub from being exploited on any network where the mini-protocol is reachable.

### Proof of Concept

An attacker connects to a Peras-enabled node and sends a single `PerasCert` message over the object-diffusion mini-protocol:

```
PerasCert
  { pcCertRound    = <any round number>
  , pcCertBoostedBlock = <point of adversarial block>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams cert`, which executes:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
```

The certificate passes validation, is timestamped, and stored via `ChainDB.addPerasCertAsync`. Chain selection subsequently applies the Peras weight boost to the adversarial block, potentially causing the node to prefer it over the honest chain. [1](#0-0) [4](#0-3) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```
