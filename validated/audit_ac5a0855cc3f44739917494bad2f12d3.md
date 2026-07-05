### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Illegitimate Chain-Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero structural or cryptographic validation. Any unprivileged peer can inject an arbitrary `PerasCert` — with any round number and any boosted-block pointer — through the Object Diffusion mini-protocol. The certificate is accepted into the `PerasCertDB`/`ChainDB` and its weight boost is applied during chain selection, allowing an adversary to make an honest node prefer a non-canonical or adversarially-chosen chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must be passed before a certificate is stored and its weight applied to chain selection. The universal instance (the only production instance) implements it as:

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

No field of `cert` is inspected. The function ignores `pcCertRound`, `pcCertBoostedBlock`, and any cryptographic proof. It wraps the raw, unverified certificate directly into a `ValidatedPerasCert` and assigns it the full configured `perasWeight`.

This stub is wired into both production ingest paths in `PerasCert.hs`:

```haskell
(validatePerasCert mkPerasParams)   -- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams)   -- makePerasCertPoolWriterFromChainDB
``` [2](#0-1) [3](#0-2) 

`processCerts` calls this validator on every inbound certificate and, if it returns `Right`, immediately stores the result:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [4](#0-3) 

The stored `ValidatedPerasCert` carries a `vpcCertBoost` that is then consumed by `weightedSelectView` during chain selection to compute `wsvWeightBoost`, which directly influences which chain the node adopts:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

---

### Impact Explanation

An adversary who can connect to a node via the Object Diffusion mini-protocol (any unprivileged peer) can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block — including an adversarially-produced block on a minority fork.
2. Send it to the target node. `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally.
3. The certificate is stored with full `perasWeight` boost.
4. During chain selection, `weightedSelectView` adds this boost to the adversarial fork's total weight, potentially making it exceed the honest chain's weight.
5. The node switches to the adversarially-boosted chain.

This is a **chain selection manipulation** bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended Peras security assumptions. The Peras weight boost is specifically designed to be a security-critical tie-breaker; bypassing its validation inverts its purpose.

**Impact class:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

- The Object Diffusion mini-protocol for Peras certificates is a **public, unauthenticated** peer-to-peer channel; any node that connects qualifies as an attacker.
- The stub is the **only** production implementation of `validatePerasCert` (the universal `instance StandardHash blk => BlockSupportsPeras blk` covers all block types).
- The TODO comment and linked issue (`cardano-peras/issues/120`) confirm this is a known incomplete implementation that has been shipped in production code.
- No special privileges, keys, or stake are required to exploit this.

---

### Recommendation

Replace the stub `validatePerasCert` with a complete implementation that, at minimum:

1. Verifies the certificate's cryptographic signature against the claimed committee members and the boosted block.
2. Validates that `pcCertRound` falls within an acceptable window relative to the current chain tip.
3. Validates that `pcCertBoostedBlock` refers to a block that is actually present in the node's VolatileDB or ImmutableDB (i.e., a known, validated block).
4. Validates that the claimed voters constitute a valid quorum according to the current stake distribution and committee selection rules.

Until a real implementation is available, the node should refuse to accept any inbound Peras certificates from peers (i.e., return `Left PerasValidationErr` unconditionally) rather than accept all of them.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer (attacker)
  → Object Diffusion mini-protocol (PerasCert diffusion)
  → makePerasCertPoolWriterFromChainDB / makePerasCertPoolWriterFromCertDB
  → processCerts  [PerasCert.hs:164]
      calls validatePerasCert mkPerasParams cert
      → SupportsPeras.hs:353: always returns Right (ValidatedPerasCert cert fullBoost)
  → addCert stores ValidatedPerasCert with full perasWeight boost
  → ChainDB chain selection reads PerasWeightSnapshot
  → weightedSelectView adds wsvWeightBoost to adversarial fork
  → preferAnchoredCandidate / compareAnchoredFragments selects adversarial fork
  → Node switches to adversarially-boosted chain
```

A concrete reproduction on a private testnet:

1. Run two nodes A (honest) and B (adversary).
2. From B, craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a minority fork that B controls.
3. Deliver the certificate to A via the Object Diffusion protocol.
4. Observe that A's chain selection now weights B's fork higher and switches to it, despite B's fork being shorter or less dense than the honest chain. [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
