### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate, Bypassing All Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no actual validation. This is the function wired into the production inbound-certificate processing pipeline. An unprivileged peer can send a crafted `PerasCert` over the mini-protocol, and it will be accepted, stored, and used to apply a Peras weight boost to an adversarially chosen block, corrupting chain selection.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must be passed before a certificate is stored and its weight boost applied. The universal instance — which is the only instance in the codebase and is therefore the one used in all production code paths — is:

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

No field of `cert` is inspected. The function ignores the certificate's round number, the block it purports to boost, any quorum proof, any committee membership proof, and any cryptographic signature. Every certificate, regardless of content or origin, is wrapped in `ValidatedPerasCert` and returned as `Right`.

This validated certificate is then assigned a weight boost equal to `perasWeight params`: [2](#0-1) 

The production inbound-certificate pipeline in `processCerts` calls this function on every new certificate received from a peer, and adds all `Right` results to the database: [3](#0-2) 

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass `validatePerasCert mkPerasParams` as the validation callback: [4](#0-3) 

The `makePerasCertPoolWriterFromChainDB` variant additionally forwards the accepted certificate to `ChainDB.addPerasCertAsync`, directly triggering chain selection side-effects.

---

### Impact Explanation

This is a **critical bypass of Peras certificate validation**. The `ValidatedPerasCert` type is the consensus layer's proof that a certificate has been checked. By unconditionally constructing this proof for any input, the validation gate is structurally present but semantically absent.

Concrete impact:

1. **Unauthorized weight boost on an adversarially chosen block.** The accepted certificate carries `vpcCertBoost = perasWeight params`. Chain selection adds this boost to whatever block `pcCertBoostedBlock` names. An adversary can name any block — including one on a minority or adversarial fork — and cause honest nodes to prefer it over the canonical chain.

2. **Bypass of all Peras certificate checks.** The checks that should be enforced — quorum (≥ 3/4 of stake), committee membership, VRF-based sortition, cryptographic signatures — are entirely absent. This directly satisfies the disqualifying condition's inverse: it is a bypass of "Peras voting or certificate checks … that enables unauthorized … certificate acceptance."

3. **Chain selection corruption.** Because `addPerasCertAsync` is called, the corrupted certificate immediately participates in chain selection, potentially causing the node to permanently prefer a non-canonical chain.

---

### Likelihood Explanation

The attack requires only that a peer send a `PerasCert` message over the Peras certificate mini-protocol. No stake, no keys, no prior knowledge of the chain is required. The adversary constructs a `PerasCert` with `pcCertBoostedBlock` pointing to any block they wish to boost and `pcCertRound` set to any round not already in the database. The certificate passes "validation" and is stored. This is reachable from any unprivileged network peer as soon as the Peras diffusion layer is active.

---

### Recommendation

Replace the stub implementation with real validation. At minimum, `validatePerasCert` must verify:

1. The certificate's quorum proof: that the aggregate stake of the signers exceeds `perasQuorumStakeThreshold`.
2. Committee membership: each signer was selected by the VRF-based sortition for the claimed round.
3. Cryptographic signatures: each signer's signature over the certificate content is valid.
4. Round number plausibility: the round is within the expected range relative to the current chain tip.

Until real validation is implemented, the inbound certificate pipeline should reject all externally received certificates (e.g., by making `validatePerasCert` return `Left PerasValidationErr` unconditionally) rather than accept them all.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to the target node and establishes the Peras certificate mini-protocol session.
2. Peer sends a `PerasCert` with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <point of an adversarial fork block>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` without inspecting any field of `cert`.
5. The certificate is stored in the `PerasCertDB` and forwarded to `ChainDB.addPerasCertAsync`.
6. Chain selection applies `vpcCertBoost` to `pcCertBoostedBlock`, causing the node to prefer the adversarial fork.

The root cause is at: [5](#0-4) 

The production call site is at: [6](#0-5)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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
