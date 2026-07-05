### Title
`validatePerasCert` Unconditionally Accepts Any Certificate Without Cryptographic Verification - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a function that always returns `Right` (valid), unconditionally wrapping any inbound certificate in a `ValidatedPerasCert` without performing any cryptographic or structural checks. This is the direct analog of the `setRole()` bug: just as `_setRole()` always performs a bitwise OR regardless of the `status` parameter (making revocation impossible), `validatePerasCert` always returns success regardless of the certificate's content (making rejection impossible). Any certificate sent by an unprivileged peer is accepted as fully validated.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal instance `instance StandardHash blk => BlockSupportsPeras blk` defines `validatePerasCert` as:

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

This function unconditionally returns `Right`, wrapping every inbound `PerasCert` in the `ValidatedPerasCert` newtype regardless of:
- Aggregate BLS signature validity
- Voter eligibility proofs
- Round number plausibility
- Boosted block point existence or validity

The `ValidatedPerasCert` wrapper is the type-level guarantee that a certificate has passed cryptographic scrutiny. Because the validation function never actually checks anything, this guarantee is hollow: any peer can send a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` with arbitrary `r` and `p`, and the node will treat it as a fully validated certificate.

The same instance also defines `validatePerasVote` to check only stake-distribution membership, ignoring the BLS vote signature and VRF eligibility proof entirely:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

Because voter IDs (`PerasVoterId`) are public, any peer can impersonate any committee member and cast votes for arbitrary blocks without possessing the corresponding private key.

The inbound certificate processing path in `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert` calls `validatePerasCert` directly, and the inbound vote processing path in `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasVote` calls `validatePerasVote` via `processVotes`. Both paths are reachable by any unprivileged network peer through the Peras object-diffusion mini-protocol.

---

### Impact Explanation

Peras certificates boost specific blocks, directly influencing chain selection: a node that holds a certificate for block `B` in round `r` will prefer chains that include `B` over chains of equal or slightly greater length. An attacker who can inject arbitrary accepted certificates can:

1. Force an honest node to prefer an attacker-chosen block, causing chain-selection divergence from the honest majority.
2. Manufacture certificates for rounds that have not yet occurred, pre-empting legitimate quorum formation.
3. Manufacture certificates boosting a block on a minority fork, causing the node to permanently diverge from the canonical chain.

This matches the **Critical** impact class: bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

The attack requires only network connectivity to a target node running the Peras object-diffusion mini-protocol. No stake, no keys, and no privileged access are needed. The attacker constructs a `PerasCert` CBOR message with chosen `pcCertRound` and `pcCertBoostedBlock` fields and sends it over the wire. The universal instance is the only `BlockSupportsPeras` instance in the repository (grep confirms `validatePerasCert` appears only in `SupportsPeras.hs` and `PerasCert.hs`), so there is no more-specific Cardano instance that would override this behavior.

---

### Recommendation

Replace the stub body of `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over the election identifier and boosted block hash against the declared voter set.
2. Checks each voter's eligibility proof (VRF output for non-persistent members, committee membership for persistent members).
3. Confirms the round number falls within the acceptable window.
4. Confirms the boosted block point is known to the local chain.

Until a real implementation is available, the function should return `Left PerasValidationErr` by default (fail-closed) rather than `Right` (fail-open), so that unverified certificates are rejected rather than silently accepted.

Similarly, `validatePerasVote` must verify the BLS vote signature and the VRF eligibility proof before returning `Right`.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  PerasCert { pcCertRound = 999, pcCertBoostedBlock = <attacker-chosen point> }
  │  (sent via Peras object-diffusion mini-protocol)
  ▼
processInboundCert (PerasCert.hs)
  │
  │  calls validatePerasCert params cert
  ▼
validatePerasCert params cert          -- SupportsPeras.hs:353-358
  = Right ValidatedPerasCert           -- ALWAYS succeeds, no checks performed
      { vpcCert = cert
      , vpcCertBoost = perasWeight params }
  │
  ▼
Certificate stored in PerasCertDB as "validated"
  │
  ▼
Chain selection consults cert DB:
  latestCertSeen = NotOrigin <attacker cert>
  → node boosts attacker-chosen block
  → node diverges from honest majority chain
```

The `ValidatedPerasCert` wrapper that downstream chain-selection code trusts as a proof of cryptographic validity is produced without any cryptographic check, exactly as `setRole(alice, 1, false)` in the Winnables report produced a role grant instead of a revocation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-177)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/API.hs (L41-70)
```haskell
data PerasVoteDB m blk = PerasVoteDB
  { addVote ::
      WithArrivalTime (ValidatedPerasVote blk) ->
      STM m (m (AddPerasVoteResult blk))
  -- ^ Add a Peras vote to the database. The result indicates whether the vote
  -- was actually added, or if it was already present.
  --
  -- NOTE: the resulting computation over 'm' is there solely for tracing
  -- purposes. Use the `join . atomically` pattern to consume its output.
  , getVoteIds ::
      STM m (Set (PerasVoteId blk))
  -- ^ Get the set of all vote IDs currently in the database.
  , getVotesAfter ::
      PerasVoteTicketNo ->
      STM m (Map PerasVoteTicketNo (WithArrivalTime (ValidatedPerasVote blk)))
  -- ^ Get all votes with a ticket number strictly greater than the given one,
  -- in ascending order.
  , getForgedCertForRound ::
      PerasRoundNo ->
      STM m (Maybe (ValidatedPerasCert blk))
  -- ^ Get the certificate if quorum was reached for the given round.
  , garbageCollect ::
      SlotNo ->
      STM m (m ())
  -- ^ Garbage-collect votes whose target slot is strictly smaller than
  -- the given slot number.
  --
  -- NOTE: the resulting computation over 'm' is there solely for tracing
  -- purposes. Use the `join . atomically` pattern to consume its output.
  }
```
