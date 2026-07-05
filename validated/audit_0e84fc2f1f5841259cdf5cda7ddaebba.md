### Title
Peras Certificate Validation Unconditionally Accepts All Certificates Without Cryptographic or Semantic Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right`, accepting every inbound Peras certificate without performing any cryptographic signature verification, committee membership check, quorum check, or any other semantic validation. Any unprivileged peer can send a crafted `PerasCert` targeting an arbitrary block, which will be accepted, stored, and used to boost that block's weight in chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a certificate before it is stored and used to influence chain selection. The universal instance (used for all block types in production) implements this gate as:

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

This unconditionally returns `Right` for every certificate, regardless of its content. No BLS aggregate signature is verified, no committee membership is checked, no quorum threshold is enforced, and no round-number or boosted-block plausibility is tested. [1](#0-0) 

This instance is the one wired into both production certificate ingest paths. `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` both call `processCerts` with `validatePerasCert mkPerasParams` as the validation function: [2](#0-1) [3](#0-2) 

`processCerts` passes each certificate through `validateCert` and, if it returns `Right`, timestamps it and adds it to the database: [4](#0-3) 

Once stored, the certificate's boost weight is returned by `getWeightSnapshot` and used directly in chain selection to prefer the boosted block over competing chains: [5](#0-4) 

The `PerasCert` type that a peer sends over the wire carries a `pcBoostedBlock` field (an arbitrary block point) and a `pcRoundNo`. Because `validatePerasCert` never inspects these fields, a peer can target any block hash it chooses. [6](#0-5) 

The concrete BLS certificate type (`Peras.Cert.V1.PerasCert`) carries a full `AggregateVoteSignature` and a `PerasCertVoters` map, but these are never verified by the production path because `validatePerasCert` returns `Right` before inspecting them: [7](#0-6) 

The analog to the reported `PersonalAccountRegistry` bug is exact: just as `_verifySender` only checked `accounts[account].owners[owner].added` and never checked `removedAtBlockNumber`, `validatePerasCert` is supposed to check the certificate's validity but instead always returns success — the check that should enforce the invariant is simply absent.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A crafted `PerasCert` with `pcCertBoostedBlock` pointing to an adversarial or minority-fork block is accepted unconditionally and stored with a boost weight of `perasWeight params` (currently 15 blocks' worth of weight). Chain selection compares candidate chains using this boosted weight. A node that has accepted the fake certificate will prefer the adversarially boosted chain over the honest canonical chain, causing it to diverge from the rest of the network. Because the certificate is persisted in `PerasCertDB`, the divergence survives restarts.

---

### Likelihood Explanation

**High.** The attack requires only that an adversary connect to a node and send a single well-formed (but cryptographically invalid) `PerasCert` message over the Peras certificate mini-protocol. No stake, no keys, and no privileged access are required. The `PerasCert` wire format is public. The `processCerts` path is exercised for every inbound certificate batch, so the vulnerable code is on the hot path for every node running Peras.

---

### Recommendation

Implement full certificate validation inside `validatePerasCert` before the TODO placeholder is shipped to a Peras-enabled network. At minimum this must include:

1. Verifying the BLS aggregate signature (`pcSignature`) against the aggregated public keys of the claimed voters.
2. Verifying that each claimed voter is a legitimate committee member for the given round (seat index within bounds, correct persistent/non-persistent classification).
3. Verifying that the total stake of the voters meets the quorum threshold.
4. Verifying that `pcRoundNo` and `pcBoostedBlock` are plausible given the current chain state.

The `implVerifyCert` functions in `Committee.WFALS` and `Committee.EveryoneVotes` already implement the correct cryptographic checks and should be wired into the `BlockSupportsPeras` instance via the `PerasCertCompatibleWithVotingCommittee` conversion layer. [8](#0-7) 

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to a target node's Peras certificate mini-protocol endpoint.
2. Construct a `PerasCert` (using the `Peras.Cert.V1` CBOR encoding) with:
   - `pcRoundNo` = any valid round number
   - `pcBoostedBlock` = the hash of a block on a minority fork
   - `pcVoters` = any non-empty bitmap (e.g., seat 0 only)
   - `pcSignature` = a zeroed or random BLS signature (will not be checked)
3. Send the certificate to the target node.
4. Observe via the node's chain selection trace that the minority-fork block now carries a `perasWeight` (15) boost.
5. If the minority fork is otherwise equal in length to the canonical chain, the node switches to it.

The root cause is confirmed at: [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L483-494)
```haskell
-- | Verify a certificate attesting the winner of a given election
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```
