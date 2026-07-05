### Title
Peras Certificate and Vote Validation Bypass via Unconditional `validatePerasCert` / `validatePerasVote` in Degenerate `BlockSupportsPeras` Instance — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance used for all block types unconditionally accepts every inbound Peras certificate (`validatePerasCert` always returns `Right`) and accepts votes based solely on a stake-distribution lookup, with no cryptographic signature or eligibility-proof verification. Both functions are wired directly into the production inbound handlers (`makePerasCertPoolWriterFromChainDB`, `makePerasVotePoolWriterFromChainDB`) that process objects received from unprivileged peers over the object-diffusion mini-protocol. An attacker can therefore inject arbitrary Peras certificates and votes, bypassing all quorum and cryptographic checks, and influence chain selection.

---

### Finding Description

The degenerate `instance StandardHash blk => BlockSupportsPeras blk` at lines 320–389 of `SupportsPeras.hs` is the only `BlockSupportsPeras` instance present in the production codebase. It provides two critically incomplete validation functions:

**1. `validatePerasCert` — unconditional acceptance**

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

Every certificate, regardless of content, is accepted and assigned a chain-weight boost equal to `perasWeight params`. No checks are performed on:
- cryptographic validity of the certificate
- quorum (whether enough committee members actually signed)
- the boosted block's existence or validity on chain
- the round number's plausibility [1](#0-0) 

**2. `validatePerasVote` — stake-lookup only, no signature check**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check is whether the claimed `pvVoteVoterId` appears in the stake distribution. The degenerate `PerasVote` type carries no signature field at all, so there is nothing to verify cryptographically. Any peer that knows a valid voter ID (which is public information from the stake distribution) can forge votes for that voter. [2](#0-1) 

**3. Production inbound path wires directly to these stubs**

`processCerts` in `PerasCert.hs` is the inbound handler for certificates received from peers. Both production writers call it with `validatePerasCert mkPerasParams`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

`processCerts` itself is correct in structure — it calls `validateCert` on each certificate and rejects the batch on any failure — but the validation function it is given always succeeds: [4](#0-3) 

The same pattern applies to votes via `makePerasVotePoolWriterFromChainDB`: [5](#0-4) 

---

### Impact Explanation

Peras certificates provide a chain-weight boost (`vpcCertBoost`) that is used in chain selection. A certificate accepted into the `PerasCertDB` or `ChainDB` for a given round boosts the weight of the certified block's chain. Because `validatePerasCert` always returns `Right`, an unprivileged peer can:

1. Craft a `PerasCert` naming any block point and any round number.
2. Send it over the object-diffusion mini-protocol.
3. Have it accepted unconditionally and stored with a full chain-weight boost.

This lets an attacker make an honest node prefer a non-canonical or adversarially-chosen chain over the honest chain, directly undermining Peras's chain-selection security guarantees. This matches the **Critical** impact class: bypass of Peras certificate/vote checks enabling unauthorized certificate acceptance, and the **High** impact class: chain-selection bug letting an unprivileged peer cause an honest node to prefer a non-canonical chain.

---

### Likelihood Explanation

The attack path requires only a network connection to a node running with Peras enabled. No keys, stake, or privileged access are needed. The attacker only needs to know the wire format of `PerasCert` (which is CBOR-serialised and fully specified in the codebase) and a valid `Point blk` to boost. The object-diffusion mini-protocol is designed to accept objects from any connected peer. [6](#0-5) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation before the Peras object-diffusion protocol is enabled in any network. At minimum, verify: (a) the certificate's aggregate BLS signature against the claimed committee members' public keys, (b) that the number of signers and their combined stake meet the quorum threshold, and (c) that the boosted block point exists on a known chain.

2. **`validatePerasVote`**: Verify the vote's cryptographic signature (BLS) and, for non-persistent committee members, the VRF eligibility proof (`pvEligibilityProof` in the V1 vote type), before accepting a vote into the `PerasVoteDB`.

3. **Guard the inbound handlers**: Until full validation is implemented, the object-diffusion inbound handlers for Peras objects should be disabled or gated behind a feature flag that is off by default, so that the stub validation cannot be reached from the network. [7](#0-6) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Connect to a Cardano node with Peras enabled via the standard node-to-node protocol.
2. The object-diffusion mini-protocol for Peras certificates is negotiated.
3. Send a crafted `PerasCert` message:
   ```
   PerasCert
     { pcCertRound    = <any round number>
     , pcCertBoostedBlock = <point of a minority-chain block>
     }
   ```
   serialised as CBOR per the `Serialise (PerasCert blk)` instance.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in the `PerasCertDB` / `ChainDB` with a full chain-weight boost.
6. Chain selection now treats the minority-chain block as having additional Peras weight, potentially causing the node to switch to the attacker's preferred chain.

The root cause — `validatePerasCert` returning `Right` for all inputs — is a necessary step in this path; without it, the certificate would be rejected before storage. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-148)
```haskell
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
