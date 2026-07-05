### Title
Peras Certificate Validation Unconditionally Accepts Any Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The global degenerate `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, performing zero cryptographic or semantic checks. Both production inbound-certificate pool writers call this stub as their sole validation gate. An unprivileged peer can therefore inject an arbitrary `PerasCert` — pointing to any block, for any round — and the node will accept it as "validated," add it to the `PerasCertDB`/`ChainDB`, and apply its chain-weight boost during chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate before a certificate is stored:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only live instance — the global degenerate one used for all block types — implements it as:

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

No BLS aggregate-signature check, no committee-membership check, no round-validity check, no quorum check — the function body ignores `cert` entirely and always returns `Right`.

Both production inbound pool writers pass this stub directly as the `validateCert` argument to `processCerts`:

```haskell
-- makePerasCertPoolWriterFromChainDB (production path)
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert` is the only guard before `addCert` is called:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, `partitionEithers` always produces `([], validatedCerts)`, so every inbound certificate — regardless of content — is unconditionally added to the database.

The `PerasCert blk` type in the degenerate instance carries only a round number and a target block point; it has no signature field at all, so there is nothing to verify even in principle:

```haskell
data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
``` [4](#0-3) 

Once accepted, the certificate is forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection with the certificate's weight boost (`vpcCertBoost = perasWeight params`): [5](#0-4) 

---

### Impact Explanation

Peras certificates exist specifically to boost the chain weight of a target block. An accepted certificate causes the node to prefer the chain containing `pcCertBoostedBlock` over competing chains that lack a certificate boost. Because `validatePerasCert` never rejects any certificate, an adversary can:

1. Craft a `PerasCert` pointing to any block of their choice (e.g., an adversarially-produced fork tip).
2. Send it via the Object Diffusion mini-protocol.
3. The receiving node accepts it, stores it, and applies its weight boost during chain selection.
4. The node may switch away from the honest canonical chain to the adversarially-boosted fork.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain by injecting a forged certificate, violating the Peras security assumption that only legitimately-quorum-certified blocks receive a boost.

---

### Likelihood Explanation

The Object Diffusion mini-protocol for Peras certificates is an externally reachable network endpoint. Any peer that can establish a node-to-node connection can send a crafted `PerasCert` message. No stake, no keys, and no prior authentication are required. The degenerate instance is the only live implementation and is used in both production pool writers. The likelihood is **High** once Peras is activated on a network running this code.

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before Peras activation. At minimum this must verify the BLS aggregate signature over `(pcCertRound, pcCertBoostedBlock)` against the aggregate public key of the claimed committee members, verify committee membership and quorum, and check that the round number is within the valid window. The concrete BLS primitives already exist in `Ouroboros.Consensus.Committee.Crypto.BLS` and `Ouroboros.Consensus.Peras.Crypto.BLS`. [6](#0-5) 

2. **Add a signature field** to the `PerasCert blk` data type in the degenerate instance (or replace the degenerate instance with a concrete Cardano-era-specific one) so that the certificate carries the data necessary for verification.

3. **Track the open issue** at `https://github.com/tweag/cardano-peras/issues/120` and ensure it is resolved before any network deployment.

---

### Proof of Concept

On a private testnet with Peras enabled and the current code:

```
-- Attacker constructs a certificate for an adversarial fork tip
let fakeCert = PerasCert
      { pcCertRound    = PerasRoundNo 42          -- any round
      , pcCertBoostedBlock = adversarialForkTip   -- attacker-chosen block
      }

-- Attacker sends [fakeCert] via the Object Diffusion protocol to the victim node.
-- processCerts calls (validatePerasCert mkPerasParams fakeCert)
-- => Right (ValidatedPerasCert { vpcCert = fakeCert, vpcCertBoost = 15 })
-- => addCert is called, certificate stored in ChainDB
-- => addPerasCertAsync triggers chain selection
-- => adversarialForkTip receives a weight boost of 15
-- => if adversarialForkTip's chain + 15 > honest chain weight, node switches forks
```

The attacker needs only a valid node-to-node connection; no keys or stake are required. The `processCerts` deduplication check (`Set.member roundNo alreadyInDb`) only prevents re-adding a certificate for the same round number, but the first injection for any fresh round number succeeds unconditionally. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L239-254)
```haskell
-- | Verify a  signature on a message with a  public key
verifyWithRole ::
  forall r msg.
  ( SignableRepresentation msg
  , HasBLSContext r
  ) =>
  PublicKey r ->
  msg ->
  Signature r ->
  Either String ()
verifyWithRole pk msg (Signature sig) =
  verifyDSIGN
    (blsCtx (Proxy @r) (publicKeyScope pk))
    (unPublicKey pk)
    msg
    sig
```
