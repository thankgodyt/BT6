### Title
Unvalidated Peer-Supplied Peras Certificate Enables Unauthorized Chain Weight Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasCert` function in the production `BlockSupportsPeras` degenerate instance unconditionally accepts any peer-supplied Peras certificate without performing any cryptographic or quorum validation. This is structurally identical to the reported `sendParam.amountLD` bug: a peer-controlled field (`pcCertBoostedBlock`) is used directly without being validated against a locally computed authoritative value (the actual quorum result). An unprivileged peer can inject a crafted certificate claiming to boost any arbitrary block, causing honest nodes to assign inflated chain weight to a non-canonical chain during Peras chain selection.

### Finding Description

**Root cause — `validatePerasCert` stub, `SupportsPeras.hs` lines 350–358:**

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

This is the **only** `BlockSupportsPeras` instance in the codebase. It is the universal instance `instance StandardHash blk => BlockSupportsPeras blk`, meaning it applies to all block types including the production Cardano block. The function takes a peer-supplied `PerasCert blk` and returns it wrapped in `ValidatedPerasCert` with zero validation. The `vpcCert = cert` line passes the peer-controlled `pcCertBoostedBlock` field through unchanged.

**Attacker-controlled entry path — `processCerts`, `PerasCert.hs` lines 156–185:**

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

Because `validateCert` is `validatePerasCert` and that function always returns `Right`, every certificate in `certsNotAlreadyInDb` passes validation and is added to the database. The `validateCert` parameter is wired to `validatePerasCert` in both `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` (lines 111 and 141 of `PerasVote.hs`).

**Structural analog to the reported bug:**

| External report | This codebase |
|---|---|
| `sendParam.amountLD` (peer-controlled) | `pcCertBoostedBlock` (peer-controlled) |
| `debtOut` (computed, never checked) | actual quorum result (computed, never checked) |
| Arbitrary token minting on destination chain | Arbitrary chain weight boost on receiving node |

The `ValidatedPerasCert` produced by `validatePerasCert` carries `vpcCertBoost = perasWeight params` (a fixed local value) and `vpcCert = cert` (the peer-supplied cert). The boosted block `pcCertBoostedBlock` inside `cert` is never verified against any locally computed quorum outcome. Chain selection then uses `totalWeightOfFragment` which sums `vpcCertBoost` for every certificate whose `pcCertBoostedBlock` appears on the fragment, directly inflating the weight of whichever block the attacker names.

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer connected via the object-diffusion mini-protocol can craft a `PerasCert` naming any block as `pcCertBoostedBlock`. Because `validatePerasCert` returns `Right` unconditionally, the certificate is stored and its boost is applied during chain selection via `totalWeightOfFragment`. The attacker can:

1. Boost a minority or adversarial chain to exceed the weight of the honest chain.
2. Cause honest nodes to switch to a non-canonical chain, violating chain-selection safety.
3. Repeat across multiple rounds to sustain the attack.

This directly matches the allowed impact: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

### Likelihood Explanation

**Likelihood: Medium.**

The Peras extension is under active development and the object-diffusion mini-protocol for certificates is already wired into the production diffusion layer. The degenerate `BlockSupportsPeras` instance is the only instance in the repository and is unconditionally applied to all block types. No operator action or key compromise is required; any peer that can connect and send a `PerasCert` message triggers the path. The constraint is that Peras must be activated on the network; once it is, exploitation requires only a single crafted protocol message.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate contains a valid aggregate signature from a quorum of committee members (analogous to the fix in the external report: "set `sendParam.amountLD` to `debtOut` instead of the user-specified value").
2. Checks that `pcCertBoostedBlock` matches the block that the verified quorum actually voted for.
3. Validates the certificate against the epoch's stake distribution and committee selection output.

Until a real implementation exists, the `processCerts` inbound path should reject all certificates rather than accept them unconditionally.

### Proof of Concept

On a private testnet with Peras enabled:

```haskell
-- Craft a certificate boosting an adversarial block
let fakeCert = PerasCert
      { pcCertRound      = currentRound
      , pcCertBoostedBlock = adversarialBlockPoint  -- attacker-chosen
      }

-- Send via the object-diffusion mini-protocol to an honest node.
-- validatePerasCert will return Right without any check:
--   validatePerasCert params fakeCert
--   = Right ValidatedPerasCert { vpcCert = fakeCert
--                               , vpcCertBoost = perasWeight params }
--
-- processCerts adds it to the cert DB.
-- totalWeightOfFragment now counts perasWeight for adversarialBlockPoint.
-- Chain selection prefers the adversarial chain.
```

The degenerate instance at [1](#0-0)  unconditionally returns `Right` for any peer-supplied certificate, with `vpcCert = cert` passing the unvalidated `pcCertBoostedBlock` through directly.

The inbound processing path at [2](#0-1)  calls `validateCert` on every peer-supplied certificate and adds all that return `Right` to the database — which is every certificate given the stub.

The chain weight computation at [3](#0-2)  sums `vpcCertBoost` for all certificates whose boosted block appears on the fragment, directly translating the accepted fake certificate into a chain selection advantage.

The `ValidatedPerasCert` type carrying the unvalidated peer field is defined at [4](#0-3) .

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-219)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks

data ValidatedPerasVote blk = ValidatedPerasVote
  { vpvVote :: !(PerasVote blk)
  , vpvVoteStake :: !PerasVoteStake
  }
  deriving stock (Show, Eq, Ord, Generic)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```
