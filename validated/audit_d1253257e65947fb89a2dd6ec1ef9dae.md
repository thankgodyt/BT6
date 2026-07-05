### Title
`validatePerasCert` Stub Unconditionally Accepts All Peras Certificates Without Validation, Enabling Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance in `SupportsPeras.hs` provides a degenerate stub where `validatePerasCert` unconditionally returns `Right` (valid) for every certificate it receives, performing zero cryptographic or committee-membership checks. Because the production Peras object-diffusion pipeline (`makePerasCertPoolWriterFromChainDB`) feeds peer-supplied certificates directly through this stub, any unprivileged peer can inject arbitrary forged Peras certificates that are stored in the `PerasCertDB` and subsequently used to boost block weights in chain selection, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

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

No BLS signature is verified, no committee-membership check is performed, no round-number bounds are enforced, and no boosted-block validity is confirmed. Every certificate is stamped `ValidatedPerasCert` with the full `perasWeight` boost (currently 15).

**Inbound pipeline — peer certificates reach the stub without any prior filter:**

`processCerts` in `PerasCert.hs` calls the validation function and, because it always returns `Right`, every certificate in the batch is accepted and forwarded to `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

The production writer (`makePerasCertPoolWriterFromChainDB`) wires this directly to the live `ChainDB`:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [3](#0-2) 

**Chain-selection impact — accepted certificates directly boost block weight:**

Stored certificates are converted into a `PerasWeightSnapshot` and used in `WeightedSelectView.wsvTotalWeight`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

Chain selection then prefers the fragment with the higher total weight:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
``` [5](#0-4) 

A single injected certificate adds `perasWeight = 15` to the attacker's chain. With enough forged certificates (one per round), the attacker can accumulate an unbounded weight advantage over the honest chain.

**Analogy to the external report:** Just as `Guard.sol` checked `safeTransferFrom`, `transferFrom`, and `approve` but omitted `burn`/`burnFrom`, the Peras inbound pipeline checks "is this cert already in the DB?" but omits every substantive validity check (signature, committee membership, round validity, boosted-block existence).

---

### Impact Explanation

**Severity: High — chain-selection manipulation by an unprivileged peer.**

An attacker with a standard peer connection can:
1. Craft `PerasCert` objects pointing to any block on their fork.
2. Send them via the Peras object-diffusion mini-protocol.
3. Because `validatePerasCert` always returns `Right`, all certificates are stored.
4. The stored certificates boost the attacker's fork weight by `perasWeight` (15) per certificate per round.
5. The honest node's chain-selection logic (`preferCandidate`) switches to the heavier fork.

This satisfies the allowed impact: *"Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

**Conditional on Peras object-diffusion being enabled in the deployed node configuration.** The production writer `makePerasCertPoolWriterFromChainDB` is fully wired up and calls the stub validator. The `PerasCert` data type is serialisable and diffusable over the network. No privileged access, key material, or stake is required — only a standard peer connection. The attack is deterministic and repeatable.

One partial mitigant: `getPerasCertInBlock _ = Nothing` means certificates are not yet extracted from on-chain blocks, so the attacker cannot anchor forged certificates to immutable chain history. However, the object-diffusion path is independent of block extraction and remains fully open.

---

### Recommendation

Replace the stub with real validation before the Peras object-diffusion protocol is enabled in production. At minimum, `validatePerasCert` must verify:

1. **BLS aggregate signature** over the certificate's round number and boosted-block point, against the claimed committee's public keys.
2. **Committee membership and quorum**: the signers must constitute a valid quorum of the elected committee for that round.
3. **Round-number bounds**: the certificate's round must be within the current `perasCertMaxRounds` window.
4. **Boosted-block existence**: the `pcCertBoostedBlock` point must refer to a block that is on the node's current chain or a known candidate fragment.

Until these checks are implemented, the Peras object-diffusion mini-protocol should be disabled at the network-negotiation layer to prevent the inbound path from being reachable.

---

### Proof of Concept

```
1. Attacker node connects to honest node via the Peras cert object-diffusion mini-protocol.

2. Attacker constructs a batch of PerasCert values:
     [ PerasCert { pcCertRound = r, pcCertBoostedBlock = attackerForkTip }
     | r <- [0 .. N] ]
   where attackerForkTip is the tip of the attacker's fork.

3. Attacker sends the batch.  processCerts calls:
     validatePerasCert mkPerasParams cert  -- always returns Right

4. All N+1 certificates are stored in PerasCertDB with boost = 15 each.

5. implGetWeightSnapshot converts them into a PerasWeightSnapshot where
   attackerForkTip carries weight 15*(N+1).

6. On the next chain-selection trigger, WeightedSelectView computes:
     wsvTotalWeight(honest)   = blockNo(honest)   + 0
     wsvTotalWeight(attacker) = blockNo(attacker) + 15*(N+1)

7. For N >= ceil(blockNo(honest) - blockNo(attacker)) / 15, the attacker's
   fork wins chain selection and the honest node switches to it.
``` [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

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
