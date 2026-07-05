### Title
Unconditional `validatePerasCert` Stub Accepts Any Peer-Supplied Peras Certificate Without Validation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` default instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. This stub is wired directly into the production inbound-certificate processing path (`processCerts` in `ObjectPool/PerasCert.hs`), which handles certificates received from untrusted network peers. An unprivileged peer can therefore inject an arbitrary `PerasCert` — with any round number and any boosted block point — and have it accepted, stored, and used to influence Peras chain-selection weight.

---

### Finding Description

**Root cause — unconditional acceptance in `validatePerasCert`:**

The `BlockSupportsPeras` instance defined at line 320 of `SupportsPeras.hs` is explicitly labelled a "degenerate instance for all blks to get things to compile." Its `validatePerasCert` method (lines 353–358) always returns `Right` without inspecting the certificate at all:

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

No voter-list length check, no quorum threshold check, no signature verification, no round-number plausibility check — nothing.

**Production wiring — `processCerts` uses this stub:**

`processCerts` in `ObjectPool/PerasCert.hs` (lines 156–185) is the function that handles batches of inbound `PerasCert` objects received from peers over the Peras certificate mini-protocol. It is called from both `makePerasCertPoolWriterFromCertDB` (line 103) and `makePerasCertPoolWriterFromChainDB` (line 126), both of which pass `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
```

Inside `processCerts`, the logic is:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert` is the stub that always returns `Right`, `partitionEithers` always produces `([], validatedCerts)`, so every peer-supplied certificate is unconditionally stored.

**Analogy to the reported vulnerability class:**

The external report flags that `merkleProof.length` is never checked, so an empty (zero-element) proof is silently accepted. Here the entire validation body is absent — not just a length check but every check — making this a strict superset of the same class: an input that must satisfy structural and cryptographic invariants before acceptance has those invariants entirely unchecked.

---

### Impact Explanation

**Severity: High — chain-selection manipulation via unauthorized certificate injection.**

Peras certificates boost the chain-selection weight of the block they certify (`vpcCertBoost = perasWeight params`). A certificate stored in `PerasCertDB` or `ChainDB` causes the node to prefer the certified block's chain over competing chains of equal or slightly greater length. By injecting a crafted `PerasCert` that certifies an attacker-controlled (non-canonical) block, an unprivileged peer can cause an honest node to:

1. Assign artificially elevated Peras weight to a non-canonical chain tip.
2. Prefer that chain over the honest canonical chain during chain selection.
3. Diverge from the rest of the honest network, breaking common-prefix guarantees.

This matches the allowed impact category: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Medium-to-High.** The attack requires only:
- Network connectivity to a target node (no credentials, no stake, no keys).
- Ability to send a well-formed CBOR-encoded `PerasCert` message over the Peras certificate mini-protocol.

The `PerasCert` data type in the default instance contains only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — both trivially forgeable. No cryptographic material is required because none is checked. The only existing guard is the duplicate-round filter (`Set.member roundNo alreadyInDb`), which is trivially bypassed by using a fresh round number.

---

### Recommendation

1. **Remove or gate the stub.** The `validatePerasCert` stub must not be reachable from any production code path. Either replace it with a proper implementation before enabling the Peras certificate mini-protocol, or add a compile-time or runtime guard that prevents `processCerts` from being instantiated with the stub validator.

2. **Add a minimum voter-list length check.** When the real `PerasCert` type carries a voter map (as in the `WFALS`/`EveryoneVotes` committee implementations), `validatePerasCert` must assert that the voter map is non-empty before proceeding to signature aggregation — directly analogous to the `merkleProof.length > 0` recommendation in the source report.

3. **Enforce quorum at validation time.** `validatePerasCert` must verify that the aggregate stake of the voters in the certificate meets the quorum threshold defined in `PerasCfg`, mirroring the `votesReachQuorum` check already present in `SupportsPeras.hs` (lines 247–270) for the vote-aggregation path.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → Peras cert mini-protocol
     → makePerasCertPoolWriterFromChainDB (ObjectPool/PerasCert.hs:118)
       opwAddObjects calls processCerts (line 121–133)
     → processCerts (ObjectPool/PerasCert.hs:164)
       validateCert = validatePerasCert mkPerasParams  ← always Right
     → partitionEithers → ([], [crafted cert])
     → addCert (ChainDB.addPerasCertAsync)
     → PerasCertDB stores cert with boost = perasWeight params
     → chain selection now weights attacker's block higher
```

**Minimal crafted certificate (default instance):**

```haskell
craftedCert :: PerasCert SomeBlk
craftedCert = PerasCert
  { pcCertRound      = PerasRoundNo 999   -- any fresh round
  , pcCertBoostedBlock = someNonCanonicalPoint  -- attacker's block
  }
-- validatePerasCert params craftedCert == Right (ValidatedPerasCert craftedCert boost)
-- No signature, no quorum, no voter list required.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L247-270)
```haskell
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-133)
```haskell
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
