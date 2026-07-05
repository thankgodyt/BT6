### Title
Peras Certificate Validation Is a No-Op Stub, Allowing Any Peer to Inject Fraudulent Chain-Boosting Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass instance used in all production code paths implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every certificate without performing any cryptographic verification, quorum check, or committee membership validation. Because this function is called directly on inbound peer-supplied certificates in the object diffusion mini-protocol, any unprivileged peer can inject a crafted `PerasCert` that boosts an arbitrary block, corrupting chain selection on the receiving node.

---

### Finding Description

**Root cause — the stub validator:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the only concrete `BlockSupportsPeras` instance (lines 318–389) implements `validatePerasCert` as:

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

No signature is checked. No quorum is verified. No committee membership is confirmed. Every certificate, regardless of origin or content, is unconditionally promoted to `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**Production entry path — peer-supplied certificates:**

`makePerasCertPoolWriterFromChainDB` (the production writer, as distinguished from the test-only `makePerasCertPoolWriterFromCertDB`) in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` (lines 113–137) passes this stub directly as the validation function:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

This is fed into `processCerts` (lines 156–185 of the same file), which is the handler for inbound Peras certificates received from remote peers via the object diffusion mini-protocol. The flow is:

```
Remote peer
  → object diffusion mini-protocol
  → processCerts
  → validatePerasCert (always Right)
  → ChainDB.addPerasCertAsync
  → chain selection applies vpcCertBoost to pcCertBoostedBlock
```

**Exploit flow:**

1. Attacker connects to an honest node as a normal peer (no keys, no stake required).
2. Attacker crafts a `PerasCert` with `pcCertBoostedBlock = <adversarial block point>` and `pcCertRound = <any round not yet in DB>`.
3. Attacker sends this certificate via the object diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is stored in the `ChainDB` / `PerasCertDB`.
6. Chain selection applies the `PerasWeight` boost to the adversarially-chosen block, potentially making the node prefer a non-canonical chain over the honest chain.

---

### Impact Explanation

**Severity: High — chain selection bug.**

A `ValidatedPerasCert` with a non-zero `vpcCertBoost` directly influences chain selection: the boosted block's effective weight is increased by `vpcCertBoost`, which can cause the node to prefer a shorter or otherwise weaker adversarial chain over the honest canonical chain. This is precisely the security invariant Peras certificates are supposed to *strengthen*, not undermine. An attacker with no stake and no cryptographic keys can trigger this by sending a single crafted network message, making the impact reachable by any unprivileged peer.

This falls squarely within: *"High. Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**High.** The object diffusion mini-protocol is a standard peer-to-peer channel. Any node that connects as a peer can send `PerasCert` objects. There is no rate limiting, no stake requirement, and no cryptographic barrier — the validation function is a compile-time stub that always succeeds. The attacker needs only a valid TCP connection to a Cardano node running this code.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that:
1. Verifies the aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the aggregated public keys of the claimed committee members.
2. Confirms that the claimed voters constitute a quorum (total stake ≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
3. Verifies VRF eligibility proofs for any non-persistent committee members included in the certificate.

The `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert` functions in the `Committee` subsystem already implement this logic correctly and should be wired into the `BlockSupportsPeras` instance once the HFC plumbing (tracked in issue #73) is in place.

---

### Proof of Concept

```
-- Attacker constructs a minimal crafted certificate:
let fraudCert = PerasCert
      { pcCertRound       = PerasRoundNo 42          -- any round not yet in DB
      , pcCertBoostedBlock = adversarialBlockPoint    -- attacker's chosen block
      }

-- Attacker sends [fraudCert] via the object diffusion mini-protocol.
-- On the receiving node, processCerts calls:
validatePerasCert mkPerasParams fraudCert
-- => Right ValidatedPerasCert
--        { vpcCert      = fraudCert
--        , vpcCertBoost = perasWeight mkPerasParams  -- full boost, no checks
--        }

-- The cert is stored and chain selection boosts adversarialBlockPoint
-- by perasWeight, potentially causing the node to switch to the
-- adversarial chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-328)
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
