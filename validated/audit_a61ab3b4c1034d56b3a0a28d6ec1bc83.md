### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types in production implements `validatePerasCert` as an unconditional `Right`, accepting every inbound Peras certificate without performing any cryptographic or structural checks. The `PerasCfg` (params) argument is received but entirely ignored. Any unprivileged peer can inject a crafted `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` via the object-diffusion mini-protocol; the certificate will pass "validation," be stored in the `PerasCertDB`, and trigger chain selection that boosts the attacker-chosen block's weight, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate before a certificate is admitted to the node's state:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The single concrete instance that covers **all** block types (including production Cardano blocks) is:

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

`params` is received but never inspected. No committee membership check, no BLS/KES signature verification, no round-number sanity check, and no boosted-block existence check is performed. The function is structurally identical to the Solidity pattern in the report — the state/config is fetched and passed in, but the critical gating logic is absent. [1](#0-0) 

This stub is wired directly into the production inbound-certificate pipeline. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [2](#0-1) 

`processCerts` treats a `Right` result as proof of validity and immediately forwards the certificate to `addPerasCertAsync chainDB`, which stores it in the `PerasCertDB` and triggers chain selection: [3](#0-2) 

Chain selection then uses the certificate's boost to compute `WeightedSelectView`, potentially switching to a fork containing the attacker-specified block: [4](#0-3) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` (a block already in the node's VolatileDB) and any `pcCertRound`. Because `validatePerasCert` returns `Right` unconditionally, the certificate is stored and the boosted block receives `perasWeight params` additional weight in every subsequent chain-selection comparison. If the attacker-chosen block is on a minority fork, the artificial weight boost can cause the honest node to switch to that fork, violating chain-selection safety. This is a **chain-selection bug triggered by an unprivileged peer via the object-diffusion mini-protocol**, matching the "High" impact category: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions. If the boost is large enough to override the honest chain's block-number advantage, the impact escalates to a consensus safety failure.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is active in the production node whenever Peras is enabled. The attacker needs only a standard peer connection and the ability to send a well-formed (but cryptographically unverified) `PerasCert` CBOR message. No key material, stake, or privileged access is required. The serialisation format for `PerasCert` is public and straightforward: [5](#0-4) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation before Peras is enabled on any network. At minimum, the implementation must:

1. Verify that the certificate's `pcCertRound` is within the expected range relative to the current ledger state.
2. Verify committee membership and the aggregate BLS/KES signature over the certificate content.
3. Verify that `pcCertBoostedBlock` refers to a block that is a plausible candidate (e.g., within the current volatile window).

Until real validation is in place, the object-diffusion inbound path for `PerasCert` should reject all externally supplied certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Establish a peer connection to the target node.
2. Initiate the Peras certificate object-diffusion mini-protocol.
3. Send a CBOR-encoded `PerasCert` with:
   - `pcCertRound` = any `PerasRoundNo` not yet in the node's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of a block already in the node's VolatileDB on a minority fork
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..}` unconditionally.
5. The certificate is stored via `addPerasCertAsync chainDB`.
6. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
7. `preferAnchoredCandidate` now computes `WeightedSelectView` with the artificial boost; if `wsvTotalWeight candidate > wsvTotalWeight ours`, the node switches to the attacker's fork.

**Root cause (exact lines):** [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L77-87)
```haskell
instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
