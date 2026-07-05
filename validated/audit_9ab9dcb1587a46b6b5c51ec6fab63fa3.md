### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts All Inbound Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every certificate it receives, performing zero validation. This is wired directly into the live Peras cert inbound processing pipeline (`processCerts`), meaning any unprivileged peer can inject arbitrarily crafted Peras certificates into the ChainDB — bypassing all round, quorum, committee-membership, and cryptographic checks — and have them accepted with a full chain-selection boost weight.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

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

The function receives a `PerasCert blk` parameter — the actual certificate to be validated — but never inspects it. It returns `Right` unconditionally, assigning the full `perasWeight params` boost to every certificate regardless of its content.

**Analog to the external report:** Just as `investorExists` checked `msg.sender` (the operator) instead of `_investorWallet` (the actual investor parameter), `validatePerasCert` is supposed to validate the `cert` parameter but instead validates nothing. The entity being processed (`cert`) is never checked.

**Live inbound pipeline — `processCerts`:** [2](#0-1) 

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
```

`processCerts` calls `validatePerasCert` on every inbound certificate batch from a peer. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken: [3](#0-2) 

Every certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync` without any rejection path being reachable.

**`validatePerasVote` has the same structural gap:** [4](#0-3) 

`validatePerasVote` checks only whether the voter ID appears in the stake distribution (`lookupPerasVoteStake`), but never verifies any cryptographic signature on the vote. The degenerate `PerasVote blk` type carries no signature field at all, so the BLS proof of eligibility is structurally absent from the validated object.

---

### Impact Explanation

A `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the weight applied during Peras chain selection. By injecting fake certificates for arbitrary rounds and arbitrary block points, an attacker can:

1. Cause honest nodes to assign boost weight to a non-canonical block, making a shorter or weaker chain appear preferred under Peras chain-selection rules.
2. Pollute the CertDB with certificates for rounds that never achieved a real quorum, permanently distorting the Peras state machine (cooldown tracking, VR-1A/VR-2B voting rules) on every node that accepts the certificates.

This matches the allowed impact scope: **bypass of Peras certificate checks enabling unauthorized certificate acceptance**, with downstream chain-selection consequences.

---

### Likelihood Explanation

The attacker-controlled entry path is direct and requires no privileges:

- The Peras cert object pool writer is wired into the diffusion layer and processes batches of `PerasCert` objects received from any connected peer.
- No stake, no keys, and no operator access are required — any peer that can speak the Peras cert mini-protocol can send crafted certificates.
- The only gate (`alreadyInDb` deduplication by round number) is trivially bypassed by using a fresh `pcCertRound` value.

---

### Recommendation

Replace the stub with real certificate validation that checks, at minimum:

1. The certificate's `pcCertRound` is within the expected window relative to the current chain tip.
2. The certificate encodes a quorum of votes from eligible committee members for the claimed round.
3. Each vote carries a valid BLS signature over `(roundNo, boostedBlock)` from a key whose eligibility proof (`pvEligibilityProof`) is cryptographically sound.
4. The `pcCertBoostedBlock` point is reachable on the local chain (or at least structurally valid).

Until real validation is in place, the inbound pipeline should reject all certificates rather than accept them unconditionally, to avoid polluting the ChainDB with adversarially crafted state.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer via the Peras cert mini-protocol.
2. Construct a `PerasCert` with an arbitrary `pcCertRound` (not yet in the node's CertDB) and an arbitrary `pcCertBoostedBlock` pointing to a block on a minority fork.
3. Send the certificate in a batch to the node's object pool writer.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is added to the ChainDB via `addPerasCertAsync`.
6. The Peras chain-selection logic now treats the minority-fork block as boosted, potentially causing the node to prefer a non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-372)
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
