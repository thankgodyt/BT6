### Title
`validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates Without Validation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production implementation of `validatePerasCert` in the `BlockSupportsPeras` instance unconditionally returns `Right` (success) for every certificate it receives, performing zero validation. This is the function called by `processCerts` when handling inbound Peras certificates from network peers. As a result, any unprivileged peer can inject arbitrary `PerasCert` objects — with any round number and any boosted block point — into the node's `PerasCertDB` and `ChainDB`. These fraudulent certificates then influence chain selection weight and block forging decisions, enabling a non-canonical chain to be preferred over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub in production code:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the only concrete instance of `BlockSupportsPeras` (the degenerate catch-all instance) implements `validatePerasCert` as:

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

No check is performed on the certificate's round number, the validity of the boosted block point, quorum membership, BLS/committee signatures, or any other field. Every certificate is unconditionally promoted to `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**Attacker-controlled entry path — `processCerts` in the production pool writer:**

`processCerts` is the function that handles inbound certificates received from peers over the Peras certificate mini-protocol. It calls the injected `validateCert` function on each new certificate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool writers — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — pass `validatePerasCert mkPerasParams` as the `validateCert` argument: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken, and every peer-supplied certificate is added to the database without rejection.

**Downstream effect — fraudulent certificates influence chain selection and block forging:**

Once a fraudulent `ValidatedPerasCert` is stored in the `PerasCertDB`, it is reflected in the `PerasWeightSnapshot` used during chain selection. A certificate claiming to boost an arbitrary block point causes the node to assign that block an unearned `perasWeight` advantage in chain selection comparisons.

Additionally, the `needCert` / `latestCertSeenIsNotExpired` logic in `Ouroboros.Consensus.Peras.Cert.Inclusion` reads the latest certificate seen from the DB and may include it in the next forged block, propagating the fraudulent certificate on-chain: [4](#0-3) 

The `latestCertSeenIsNotExpired` check (`currRoundNo <= _A + latestCertSeenRoundNo`) is only applied to the *forging decision*, not to the *inbound acceptance* step. An attacker can supply a certificate with a future round number that passes this check trivially, ensuring the fraudulent cert is included in the next block.

---

### Impact Explanation

**High — Chain selection and certificate verification bypass.**

An unprivileged peer can:
1. Send a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block on any fork.
2. The certificate is accepted unconditionally and stored with full `perasWeight`.
3. The node's chain selection now treats the targeted block as having a Peras boost it did not legitimately earn, potentially causing the node to prefer a non-canonical or adversary-controlled chain over the honest chain.
4. If the node is a block producer, it may include the fraudulent certificate in its next block, spreading the invalid boost to other nodes that accept the block.

This directly matches the allowed impact scope: **bypass of certificate/vote verification checks that enables unauthorized certificate acceptance**, and **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain**.

---

### Likelihood Explanation

**High.** The attack requires only a network peer connection — no keys, no stake, no privileged access. The attacker sends a single crafted `PerasCert` message. The degenerate `validatePerasCert` instance is the only instance in the codebase and is wired into both production pool writers. The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known placeholder, not an intentional design choice, meaning the missing validation is unintentional.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with actual validation that checks at minimum:
- The certificate's round number is within the valid range relative to the current chain tip.
- The boosted block point exists on the node's known chain and is not from a future or unknown slot.
- The certificate carries a valid quorum proof (BLS aggregate signature or equivalent committee attestation).
- The certificate round has not already been superseded by a later on-chain certificate.

Until real validation is implemented, inbound certificates from peers should be rejected entirely (return `Left PerasValidationErr` unconditionally) rather than accepted unconditionally, to prevent the chain selection manipulation described above.

---

### Proof of Concept

A malicious peer connects to the target node and sends a `PerasCert` message via the Peras certificate object diffusion mini-protocol with:
- `pcCertRound = currentRound + 1` (a future round the attacker controls)
- `pcCertBoostedBlock = pointOfAdversarialFork` (a block on the attacker's preferred fork)

`processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally. [5](#0-4) 

The cert is stored in the `PerasCertDB`. The `PerasWeightSnapshot` now includes a boost for `pointOfAdversarialFork`. On the next chain selection event, the node compares the honest chain (no boost) against the adversarial fork (fraudulent boost = `perasWeight`), and may select the adversarial fork as the preferred chain. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-133)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L265-286)
```haskell
-- | latestCertSeenIsNotExpired: the latest certificate seen has not yet expired
-- according to the current round number and the Peras protocol parameters
latestCertSeenIsNotExpired ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
latestCertSeenIsNotExpired
  PerasCertInclusionView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    LatestCertSeenIsNotExpired latestCertSeenRoundNo
      := Bool (currRoundNo <= _A + latestCertSeenRoundNo)
   where
    latestCertSeenRoundNo =
      lcsCertRound latestCertSeen

    _A =
      PerasRoundNo $
        unPerasCertMaxRounds $
          perasCertMaxRounds $
            perasParams
```
