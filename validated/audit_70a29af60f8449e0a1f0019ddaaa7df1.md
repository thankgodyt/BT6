### Title
Peras Certificate Validation Bypass Accepts Arbitrary Peer-Injected Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or structural validation. This stub is wired directly into the production `makePerasCertPoolWriterFromChainDB` path, which processes inbound Peras certificates received from unprivileged NTN peers via the ObjectDiffusion mini-protocol. Any peer can therefore inject arbitrary certificates into the node's `PerasCertDB` and trigger `ChainDB.addPerasCertAsync` chain-selection side-effects without possessing any valid key material or committee membership.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The degenerate catch-all instance of `BlockSupportsPeras` (introduced to make the codebase compile while Peras plumbing is in progress) implements `validatePerasCert` as:

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

Every certificate, regardless of content, is accepted and assigned the full `perasWeight` boost. [1](#0-0) 

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

The production pool writer for inbound peer certificates passes this stub directly as the validator:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

and on success calls `ChainDB.addPerasCertAsync chainDB`, which "properly handles any needed chain selection side-effects." [2](#0-1) 

**Processing path — `processCerts`:**

`processCerts` reads the validator as a plain function argument and calls it on every new certificate from the peer. Because `validatePerasCert` always returns `Right`, the `partitionEithers` branch that would throw `PerasCertValidationError` is never reached; every certificate is timestamped and forwarded to `addCert`. [3](#0-2) 

**Analog to the external report:**

The external report's scenario 2 describes `onFlashLoan()` not checking `msg.sender` or `operator`, allowing an arbitrary caller to invoke it with arbitrary data and exploit the still-active trusted execution context. Here, `processCerts` is the analogous callback: it is invoked by the ObjectDiffusion mini-protocol with peer-supplied data, and the "operator check" (`validatePerasCert`) is entirely absent. The trusted context being exploited is the node's `PerasCertDB` and the chain-selection side-effect path.

**`mkPerasParams` is a hardcoded default, not chain-derived:**

The parameters passed to the stub validator are a compile-time constant (`mkPerasParams`), not derived from the ledger state or any per-peer context. Even if the stub were replaced with a real validator, using hardcoded parameters rather than chain-derived ones would be a separate misconfiguration risk. [4](#0-3) 

---

### Impact Explanation

**Classification:** Critical — Bypass of Peras certificate validation that enables unauthorized certificate acceptance.

An unprivileged NTN peer can:

1. Craft a `PerasCert` for any `PerasRoundNo` and any `Point blk` (boosted block).
2. Send it via the ObjectDiffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB` / `ChainDB` with a `vpcCertBoost = perasWeight mkPerasParams = 15`.
5. `ChainDB.addPerasCertAsync` triggers chain-selection side-effects.

When the Peras weight snapshot is fully activated in chain selection (the `emptyPerasWeightSnapshot` TODO in `checkPreferTheirsOverOurs` is resolved), an attacker can boost an adversarially-chosen block by 15 weight units per injected certificate, potentially causing honest nodes to prefer a non-canonical chain. Even before full activation, the certificates are durably stored and will influence chain selection once the TODO is resolved, meaning the attack surface is already open. [5](#0-4) 

---

### Likelihood Explanation

**Likelihood: High.**

- The ObjectDiffusion mini-protocol is in the production source tree and is reachable by any unprivileged NTN peer.
- No key material, stake, or committee membership is required — the attacker only needs to connect and send a well-formed `PerasCert` CBOR message.
- The bypass is unconditional: there is no code path in `validatePerasCert` that can return `Left`.
- The `PerasCert` type is fully serialisable and its fields (`pcCertRound`, `pcCertBoostedBlock`) are attacker-controlled. [6](#0-5) 

---

### Recommendation

1. **Replace the stub immediately.** `validatePerasCert` must verify committee membership, quorum threshold, and BLS aggregate signature before returning `Right`. Until real validation is implemented, the ObjectDiffusion certificate ingestion path should be disabled or gated behind a feature flag that is off by default.

2. **Do not use `mkPerasParams` as the validator config.** The `PerasCfg blk` passed to `validatePerasCert` must be derived from the current ledger state (analogous to how `LedgerView` is obtained for header validation), not from a compile-time constant.

3. **Audit `makePerasCertPoolWriterFromCertDB` as well.** It uses the same stub validator and is the path used in tests against the `PerasCertDB` in isolation; if test infrastructure is ever reused in production, the same bypass applies. [7](#0-6) 

---

### Proof of Concept

```
Attacker (unprivileged NTN peer)
  │
  │  ObjectDiffusion mini-protocol
  │  sends: PerasCert { pcCertRound = <any>, pcCertBoostedBlock = <adversarial block point> }
  ▼
processCerts
  │  validateCert = validatePerasCert mkPerasParams
  │  validateCert cert  ──►  Right (ValidatedPerasCert { vpcCertBoost = 15 })
  │  (never reaches Left branch)
  ▼
addCert (WithArrivalTime now validatedCert)
  │
  ▼
ChainDB.addPerasCertAsync chainDB
  │  triggers chain-selection side-effects
  ▼
PerasCertDB stores cert with boost=15 for attacker-chosen block
  │
  ▼
When emptyPerasWeightSnapshot TODO is resolved:
  preferAnchoredCandidate uses cert weight → node prefers adversarial chain
```

The attacker needs only a valid NTN connection and the ability to serialise a `PerasCert` value (the CBOR codec is public). No cryptographic material is required. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1838-1851)
```haskell
      shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
          emptyPerasWeightSnapshot
          ourFrag
          theirFrag =
        pure ()
    | otherwise =
        throwSTM $
          CandidateTooSparse
            mostRecentIntersection
            (ourTipFromChain ourFrag)
            (theirTipFromChain theirFrag)
```
