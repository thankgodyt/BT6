### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Inbound Certificate Without Signature or Quorum Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the production `BlockSupportsPeras` instance is a stub that returns `Right` for every certificate it receives, performing no cryptographic or quorum verification whatsoever. Any unprivileged peer can send a crafted `PerasCert` for an arbitrary block via the Peras certificate diffusion mini-protocol, have it accepted by the receiving node, and cause that node's chain selection to boost the attacker-chosen block's weight — directly analogous to the GaugeController vote-weight recycling bug where missing enforcement allows a voter to apply full weight to every gauge.

---

### Finding Description

The `BlockSupportsPeras` class defines a `validatePerasCert` method that is supposed to verify an inbound Peras certificate before it is stored and used to influence chain selection. The only concrete instance in the codebase is the degenerate catch-all:

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

This stub:
- Does **not** verify the aggregate BLS signature over the certificate
- Does **not** check that the claimed voters form a valid committee
- Does **not** verify that the votes bundled in the certificate actually reach the quorum threshold
- Does **not** check that the certificate's round number is valid relative to the current chain state

The stub is wired directly into the production inbound certificate processing path via `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

which is wired into the live node-to-node handler:

```haskell
(makePerasCertPoolWriterFromChainDB systemTime getChainDB)
``` [3](#0-2) 

The `processCerts` function calls `validateCert` on each inbound certificate and, if it returns `Right`, immediately passes it to `ChainDB.addPerasCertAsync`: [4](#0-3) 

A certificate stored in the ChainDB is used to boost the weight of its target block in chain selection via `getPerasWeightSnapshot`. Because `validatePerasCert` never rejects anything, every crafted certificate is accepted and applied.

The same pattern exists for `validatePerasVote`, which also only checks stake-distribution membership and performs no signature verification: [5](#0-4) 

(Note: the vote path is currently neutralised in the live wiring by an empty stake distribution, but the cert path has no such guard.)

The `PerasVoteDB` deduplication correctly prevents the same `(voterId, roundNo)` pair from being counted twice: [6](#0-5) 

However, this deduplication is irrelevant when the upstream validation step is a no-op — an attacker does not need to replay votes; they simply forge a single certificate for any block they choose.

---

### Impact Explanation

**Critical — Bypass of certificate verification enabling unauthorized chain-selection manipulation.**

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is added to the weight of its target block during chain selection. By forging a certificate for a block on a minority fork, an attacker can make honest nodes compute that fork as heavier than the honest chain, causing them to switch to the attacker's preferred chain. This is a consensus safety failure: honest nodes diverge from the canonical chain based on a cryptographically unverified certificate injected by an unprivileged peer.

---

### Likelihood Explanation

**High.** The attack requires only:
1. A TCP connection to a target node (the Peras cert diffusion mini-protocol is open to any peer).
2. Knowledge of any valid block hash to target (publicly observable from the chain).
3. Construction of a `PerasCert` CBOR payload — a trivial serialisation exercise given the public type definition.

No stake, no keys, no prior relationship with the target node is required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature against the claimed committee members' public keys.
2. Checks that the claimed voters are members of the correct committee for the certificate's round.
3. Verifies that the total stake of the signers exceeds the configured quorum threshold (`perasQuorumStakeThreshold`).
4. Validates the certificate's round number against the current chain state (not too old, not in the future).

Until the real implementation is in place, the inbound cert diffusion handler should reject all certificates (e.g., by returning `Left` unconditionally) rather than accepting them all. The same applies to `validatePerasVote`.

---

### Proof of Concept

```
Attacker connects to an honest node via the Peras cert diffusion mini-protocol.

Attacker observes block B on a minority fork at slot S, with hash H.

Attacker constructs:
  cert = PerasCert { pcCertRound = R, pcCertBoostedBlock = BlockPoint S H }

Attacker serialises cert as CBOR and sends it as a single-element batch
via the ObjectDiffusion protocol.

On the honest node:
  processCerts → validatePerasCert mkPerasParams cert
               → Right (ValidatedPerasCert { vpcCert = cert
                                           , vpcCertBoost = perasWeight params })
  → ChainDB.addPerasCertAsync (WithArrivalTime now validatedCert)
  → getPerasWeightSnapshot now includes boost for block B
  → chain selection prefers the fork containing B over the honest chain
```

The node switches to the attacker's chosen fork without any legitimate quorum having been reached.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-174)
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
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L194-198)
```haskell
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```
