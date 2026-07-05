### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peras Certificate from Unprivileged Peers — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance, which applies to all block types including production Cardano blocks, provides a `validatePerasCert` implementation that unconditionally returns `Right` — accepting every inbound Peras certificate without any cryptographic or structural verification. This is the direct analog of the CSP report's "missing `default-src` fallback with unsafe keywords": a permissive catch-all policy that bypasses all security checks. An unprivileged peer can send a crafted `PerasCert` over the Peras diffusion mini-protocol and have it accepted as a `ValidatedPerasCert`, influencing chain selection via the Peras boosting mechanism.

---

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal instance `instance StandardHash blk => BlockSupportsPeras blk` is explicitly marked as a temporary placeholder ("TODO: degenerate instance for all blks to get things to compile") and provides the following `validatePerasCert` implementation:

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

This function takes any `PerasCert blk` from any source and wraps it in `ValidatedPerasCert` with a full `vpcCertBoost` weight, performing zero validation. There is no check of:
- Committee membership of the certificate issuer
- Cryptographic signature over the certificate content
- Round number validity or monotonicity
- Boosted block existence or validity

Because this is a universal instance (`instance StandardHash blk => BlockSupportsPeras blk`), it applies to all block types for which no more specific instance exists — including production Cardano blocks — until the per-era instances are implemented. [2](#0-1) 

**Secondary issue — `validatePerasVote` omits signature verification:**

The same universal instance's `validatePerasVote` only checks stake distribution membership (voter ID lookup), but the stub `PerasVote` data type carries no signature field at all:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound :: PerasRoundNo
  , pvVoteBlock :: Point blk
  , pvVoteVoterId :: PerasVoterId
  }
``` [3](#0-2) 

Any peer can forge a vote for any voter ID present in the stake distribution without possessing that voter's private key.

**Inbound path — `processVotes` and `implAddVote`:**

Inbound Peras votes from peers are processed via `processVotes` in `PerasVote.hs`, which calls the `validatePerasVote` stub: [4](#0-3) 

The `implAddVote` function in `PerasVoteDB/Impl.hs` itself carries a TODO acknowledging missing validation logic: [5](#0-4) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance.**

A `ValidatedPerasCert` produced by the stub carries a full `vpcCertBoost` weight (`perasWeight params`). This boost weight is used by the Peras chain selection logic to prefer boosted blocks. An unprivileged peer that sends a crafted `PerasCert` targeting an arbitrary block will have that certificate accepted as fully validated, causing honest nodes to boost and prefer a block of the attacker's choosing. This breaks the Peras safety guarantee that only legitimately elected committee members can boost blocks, enabling unauthorized chain selection manipulation without any stake majority or key compromise.

---

### Likelihood Explanation

**Likelihood: High.**

The Peras vote/certificate diffusion mini-protocol is reachable by any unprivileged peer. The stub instance is the only `BlockSupportsPeras` instance in the codebase (no per-era override exists yet for production Cardano blocks). The exploit requires only sending a well-formed `PerasCert` CBOR message — no cryptographic capability is needed. The TODO comment and linked issue confirm this is a known incomplete state, not an intentional design.

---

### Recommendation

1. **Remove the universal stub instance** (`instance StandardHash blk => BlockSupportsPeras blk`) from production code, or gate it behind a compile-time flag that prevents it from being used for production block types.
2. **Implement per-era `BlockSupportsPeras` instances** for all Cardano eras that perform full cryptographic certificate and vote verification (committee membership, BLS/VRF signature checks, round number monotonicity).
3. **Add a signature field** to the `PerasVote` and `PerasCert` data types in the universal instance, or enforce that the stub cannot be instantiated for production block types.
4. **Block inbound Peras certificate/vote processing** until proper validation is in place, rather than accepting all inputs via the stub.

---

### Proof of Concept

An attacker connects to a Cardano node running with the universal `BlockSupportsPeras` instance and sends a crafted Peras certificate message targeting block `B` (any block hash) in round `R`:

```
PerasCert { pcCertRound = R, pcCertBoostedBlock = B }
```

The node calls `validatePerasCert params cert`, which executes:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [6](#0-5) 

The certificate is stored as `ValidatedPerasCert` with full boost weight. The Peras chain selection logic now treats block `B` as boosted, preferring it over competing chains — without any committee election, VRF proof, or signature having been verified. The attacker has achieved unauthorized Peras certificate acceptance with zero cryptographic capability.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }

-- | Create a pool writer from the 'ChainDB'.
-- This properly handles the produced certs by letting the ChainDB take care
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
