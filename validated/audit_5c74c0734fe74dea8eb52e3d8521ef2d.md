### Title
Peras Certificate Validation Unconditionally Accepts Any Inbound Certificate, Enabling Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance provides a `validatePerasCert` implementation that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. An unprivileged peer can therefore inject a crafted `PerasCert` pointing at any block, have it accepted as a `ValidatedPerasCert`, and cause the receiving node to apply an artificial weight boost to that block during chain selection — potentially making the node prefer a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate and vote validation. The repository contains exactly **one** instance of this class, declared as a "degenerate instance for all blks to get things to compile":

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

This is the **only** instance in the codebase (confirmed: `grep -r "instance.*BlockSupportsPeras"` returns a single file). It is therefore the instance used in every production code path.

The inbound certificate handler in `PerasCert.hs` calls `validatePerasCert` on every certificate received from a peer. Because the function always returns `Right`, every certificate — regardless of its round number, boosted block, or any cryptographic proof — is wrapped in `ValidatedPerasCert` and stored. The stored `ValidatedPerasCert` carries a `vpcCertBoost` weight that is subsequently applied to the referenced block during Peras-weighted chain selection.

The analogous defect in `validatePerasVote` is also present: the `PerasCfg blk` (params) argument is explicitly discarded (`_params`), so no round-validity, committee-membership, or signature check is performed on inbound votes either:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [2](#0-1) 

Both the production vote-pool writer that targets the `ChainDB` and the one that targets the `PerasVoteDB` directly call `validatePerasVote mkPerasParams sd vote`, where `mkPerasParams` is a placeholder and the function ignores it anyway: [3](#0-2) 

---

### Impact Explanation

`ValidatedPerasCert` is the type that the chain-selection and weight-snapshot subsystems trust. Once a certificate is wrapped in this type it is treated as legitimate and its `vpcCertBoost` weight is applied to the referenced block. Because `validatePerasCert` never rejects anything, an adversary can:

1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to any block on any fork.
2. Transmit it to an honest node via the object-diffusion mini-protocol.
3. The node calls `validatePerasCert`, receives `Right ValidatedPerasCert`, stores it, and applies the boost.
4. Chain selection now treats the adversary-chosen block as having Peras weight, potentially making the node switch to a non-canonical or adversary-controlled fork.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The crafted certificate requires only a valid `PerasRoundNo` and a `Point blk` — both are public, unauthenticated fields. No key material, stake majority, or operator access is needed. Any peer that can open a connection and speak the object-diffusion protocol can trigger this path.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) with real implementations that verify:
- The certificate's cryptographic proof / aggregate signature.
- That the boosted block's slot falls within the correct Peras round window.
- That the certificate was produced by a legitimately elected committee (committee-selection check).
- That the round number is within the acceptable range relative to the current chain tip.

Until real validation is implemented, inbound certificates from untrusted peers should be rejected entirely rather than unconditionally accepted. The `validatePerasCert` stub should at minimum return `Left PerasValidationErr` (reject-all) rather than `Right` (accept-all) to fail safe.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to an honest node and negotiates the object-diffusion mini-protocol for Peras certificates.
2. Peer sends a `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversary fork tip> }
   ```
3. The node's inbound handler calls `validatePerasCert params cert`.
4. `validatePerasCert` executes:
   ```haskell
   Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
   ```
   — no check is performed; `Right` is always returned.
5. The `ValidatedPerasCert` is stored in the `PerasCertDB` / `ChainDB`.
6. The Peras weight snapshot now includes a boost for `pcCertBoostedBlock`.
7. Chain selection compares the adversary's fork (now boosted) against the honest chain and may switch to the adversary's fork. [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L119-152)
```haskell
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
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
