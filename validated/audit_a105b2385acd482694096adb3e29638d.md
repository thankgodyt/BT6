### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The default `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or committee-membership checks. The production inbound-certificate pipeline (`processCerts`) calls this function as the sole gate before persisting a peer-supplied certificate. An unprivileged peer can therefore inject an arbitrary `PerasCert` for any round and any block, bypassing the Peras quorum requirement entirely.

### Finding Description
The vulnerability class in the reference report is **a required precondition step that is silently absent before a consequential operation**: `Router.exactInput` required a token approval that was never performed, so the call always reverted. The analog here is that `validatePerasCert` is required to verify cryptographic and committee-membership preconditions before a certificate is accepted, but the entire body of that function is a stub that always succeeds.

In `BlockSupportsPeras.hs`, the universal default instance reads:

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

Every certificate that arrives from a peer is wrapped in `ValidatedPerasCert` and returned as `Right`, regardless of its content.

The production inbound path in `PerasCert.hs` calls this function directly:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` uses the result of `validatePerasCert` as the sole validity gate before calling `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validateCert` never returns a `Left`, the `errs` branch is unreachable and every peer-supplied certificate is unconditionally persisted.

The same pattern applies to `validatePerasVote`, which also carries a TODO stub and skips signature verification:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

For votes, a stake-distribution lookup is performed but no cryptographic signature check is done, meaning any peer that knows a valid voter ID can forge votes.

### Impact Explanation
Peras certificates are the mechanism by which a block receives a "boost" in chain selection — a certified block is preferred over an uncertified one even if the uncertified chain is longer. Accepting a forged certificate for an attacker-chosen block causes honest nodes to prefer that block in chain selection, enabling an unprivileged peer to redirect the canonical chain to an attacker-controlled tip without winning any VRF lottery or holding any stake. This is a bypass of Peras voting and certificate checks, falling under the **Critical** impact category.

### Likelihood Explanation
The object diffusion mini-protocol is wired into the production node and is reachable by any peer that can establish a connection. No special privileges, keys, or stake are required. The attacker only needs to send a well-formed `PerasCert` CBOR message; the stub validation ensures it will always be accepted. Likelihood is **High** once Peras is active on a network running this code.

### Recommendation
Replace the stub `validatePerasCert` (and `validatePerasVote`) implementations with real cryptographic and committee-membership checks before any certificate or vote is persisted. Until the real validation is implemented, the inbound pipeline should reject all externally supplied Peras objects rather than accepting them unconditionally. The existing GitHub issue [tweag/cardano-peras#120](https://github.com/tweag/cardano-peras/issues/120) tracks this work and should be treated as a security-critical blocker before Peras is enabled on any network.

### Proof of Concept
1. Attacker connects to a node via the object diffusion mini-protocol.
2. Attacker sends a `PerasCert` message for round `R` boosting an attacker-controlled block `B`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. The stub returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally.
5. `addCert` persists the certificate; the node now treats block `B` as certified for round `R`.
6. Chain selection applies the Peras boost to `B`, causing the node to prefer the attacker's chain over the honest chain. [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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
