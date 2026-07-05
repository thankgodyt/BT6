### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Fake-Cert Chain-Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that is an unconditional stub: it always returns `Right` regardless of the certificate's content, round, boosted block, or any cryptographic proof. The inbound certificate pipeline (`processCerts`) treats a `Right` result as proof of validity and immediately stores the certificate in the cert DB, which then feeds Peras weight boosts into chain selection. An unprivileged peer can therefore inject an arbitrary `PerasCert` — pointing at any block in any round — and cause an honest node to boost and prefer a non-canonical chain.

---

### Finding Description

**Root cause — stub validator always succeeds** [1](#0-0) 

The universal instance covers every concrete block type:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
```

Within that instance, `validatePerasCert` is: [2](#0-1) 

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

No signature is checked, no committee membership is verified, no quorum is confirmed. The function wraps the raw, attacker-supplied `PerasCert` directly into a `ValidatedPerasCert` and returns `Right`.

**Inbound pipeline — `processCerts` trusts the validator result** [3](#0-2) 

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

Because `validateCert` is wired to `validatePerasCert mkPerasParams` in both the `PerasCertDB`-backed and `ChainDB`-backed writers: [4](#0-3) [5](#0-4) 

…the `partitionEithers` call will always produce an empty error list, so every inbound certificate is unconditionally stored.

**Chain selection consumes the stored cert**

Once stored, the certificate is surfaced through `ChainDB.addPerasCertAsync`, which triggers a chain-selection re-evaluation that applies the Peras weight boost (`vpcCertBoost`) to the block named in `pcCertBoostedBlock`: [6](#0-5) 

The honest node will therefore prefer whichever chain contains the attacker-nominated block, even if that chain is shorter or otherwise non-canonical under the base Praos/Ouroboros rules.

**Analogous gap in vote validation**

`validatePerasVote` only checks stake-distribution membership; it performs no cryptographic signature verification either: [7](#0-6) 

An attacker who controls a pool ID present in the stake distribution can forge votes for arbitrary blocks without possessing the corresponding signing key.

---

### Impact Explanation

**Severity: High — chain-selection manipulation by an unprivileged peer.**

An unprivileged peer that can open a connection to an honest node can send a single crafted `PerasCert` naming any block it chooses. The honest node will store it as a `ValidatedPerasCert` and apply its weight boost during chain selection, causing the node to prefer the attacker's nominated chain over the canonical chain. This directly satisfies the "chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" impact category.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol for Peras certificates is reachable by any peer that can establish a node-to-node connection — no stake, no keys, no prior relationship required. The attacker needs only to serialize a valid `PerasCert` CBOR structure (a round number and a block point) and send it. The stub validator guarantees acceptance.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate cryptographic signature against the claimed committee members' public keys (using `verifyCert` from `CryptoSupportsVotingCommittee`).
2. Confirms that the claimed voters are genuine committee members for the stated round (seat-index bounds check, persistent/non-persistent membership).
3. Confirms that the aggregate stake of the verified voters meets the quorum threshold.
4. Rejects any certificate that fails any of the above checks with a typed `PerasValidationErr`.

Until the real implementation is in place, the inbound certificate pipeline should refuse all externally received certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.

The same applies to `validatePerasVote`: add signature verification before accepting a vote from a peer.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Attacker opens a node-to-node connection to an honest Cardano node.
2. Attacker sends an object-diffusion message containing a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <point of attacker's preferred block>`
3. `processCerts` is called with `validateCert = validatePerasCert mkPerasParams`.
4. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = attackerCert, vpcCertBoost = perasWeight mkPerasParams}` — no check performed.
5. `partitionEithers` yields `([], [validatedAttackerCert])`.
6. `addCert (WithArrivalTime now validatedAttackerCert)` stores the cert.
7. `ChainDB.addPerasCertAsync` triggers chain selection; the attacker's block now carries a Peras weight boost.
8. The honest node switches to the attacker's chain if its boosted weight exceeds the current selection.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
