### Title
Peras Vote Validation Uses Hardcoded Empty Stake Distribution Instead of Authoritative ChainDB Source - (File: `ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs`)

---

### Summary

The Peras vote diffusion inbound handler hardcodes `PerasVoteStakeDistr mempty` (an empty stake distribution) as the authoritative source for vote validation instead of querying the ChainDB for the current epoch's stake distribution. This is structurally identical to the external report's bug: a "controller" component uses its own stored/immutable value rather than querying the authoritative source, so the authoritative source's updates are never reflected. The consequence is that every inbound Peras vote from every peer fails validation, no Peras certificates can ever be formed from peer-sourced votes, and Peras weight boosts are permanently absent from chain selection — degrading it to pure chain length.

---

### Finding Description

In `NodeToNode.hs` at lines 398–408, the Peras vote diffusion inbound handler is wired as:

```haskell
makePerasVotePoolWriterFromChainDB
    systemTime
    -- TODO: when actual plumbing for Peras is ready, we will have to
    -- extract the committee selection data from the chainDB to pass
    -- it here, instead of relying on an empty the stake distribution.
    --
    -- Note that the empty stake distribution will cause all votes to
    -- be considered invalid.
    (pure (PerasVoteStakeDistr mempty))   -- ← hardcoded empty map
    getChainDB
``` [1](#0-0) 

The authoritative stake distribution lives in the ChainDB (updated every epoch via the ledger state), but the handler never queries it. Instead it permanently supplies an empty `Map PerasVoterId PerasVoteStake`.

`makePerasVotePoolWriterFromChainDB` closes over this STM action and passes it to `processVotes` as the `validateVote` callback:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [2](#0-1) 

`validatePerasVote` in `SupportsPeras.hs` performs a map lookup:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr = Right ...
  | otherwise = Left PerasValidationErr
``` [3](#0-2) 

`lookupPerasVoteStake` does `Map.lookup (pvVoteVoterId vote) (unPerasVoteStakeDistr distr)`. With an empty map this always returns `Nothing`, so every vote returns `Left PerasValidationErr`. [4](#0-3) 

`processVotes` then throws `PerasVoteValidationError` on any failure, disconnecting the sending peer:

```haskell
(errs, _) ->
  throw (PerasVoteValidationError errs)
``` [5](#0-4) 

The `PerasVoteDB` accumulates votes and forges a certificate when quorum is reached via `updatePerasRoundVoteStates`. Because no vote ever passes validation, `implAddVote` is never called with a valid vote, so `pvdsRoundVoteStates` never accumulates stake, quorum is never reached, and no `ValidatedPerasCert` is ever produced. [6](#0-5) 

The `PerasCertDB` therefore never receives a certificate, `getWeightSnapshot` always returns an empty `PerasWeightSnapshot`, and `preferAnchoredCandidate` — which drives chain selection — never applies any Peras weight boost. [7](#0-6) 

---

### Impact Explanation

The Peras protocol's purpose is to boost the weight of certified chains so that honest nodes converge on the canonical chain faster and resist adversarial forks. With the stake distribution permanently empty:

1. **All peer-sourced Peras votes are silently discarded** — no quorum can ever be reached from network-received votes.
2. **No Peras certificates are ever formed** — `PerasCertDB` stays empty, `getWeightSnapshot` returns `emptyPerasWeightSnapshot`.
3. **Chain selection degrades to pure chain length** — Peras weight boosts are never applied, so the node behaves as if Peras does not exist.
4. **An adversary can exploit the missing weight boosts** — by presenting a longer chain that would be outweighed under correct Peras operation, the adversary can make the node prefer a non-canonical or less-secure chain, violating the intended Peras security assumptions.

This matches the **High** allowed impact: *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

---

### Likelihood Explanation

The Peras vote diffusion mini-protocol is wired into the live node-to-node handler in `NodeToNode.hs`. Any peer that speaks the Peras vote diffusion protocol version will trigger this path. No special privileges are required — any unprivileged peer can send votes. The bug is structural and permanent for the lifetime of the process; it cannot be corrected at runtime without a code change and restart.

---

### Recommendation

Replace the hardcoded `(pure (PerasVoteStakeDistr mempty))` with an STM action that reads the current epoch's stake distribution from the ChainDB (or from the ledger state exposed by the LedgerDB). The code's own TODO comment already prescribes this fix:

> *"we will have to extract the committee selection data from the chainDB to pass it here"*

Concretely, the handler should call something equivalent to:

```haskell
ChainDB.getPerasVoteStakeDistr getChainDB
```

where `getPerasVoteStakeDistr` queries the current ledger state for the epoch-stable stake distribution used by the Peras committee selection, analogous to how `getPerasWeightSnapshot` already queries `PerasCertDB` for the live weight snapshot.

---

### Proof of Concept

1. Node A starts with the production `NodeToNode.hs` handler (empty stake distribution).
2. Peer B sends a batch of syntactically valid Peras votes for round R targeting block P.
3. Node A calls `processVotes`; `getStakeDistrSTM` returns `PerasVoteStakeDistr mempty`; every `validatePerasVote` call returns `Left PerasValidationErr`.
4. `processVotes` throws `PerasVoteValidationError`; Node A disconnects from Peer B.
5. `PerasVoteDB` on Node A has zero entries; `PerasCertDB` has zero certificates; `getWeightSnapshot` returns `emptyPerasWeightSnapshot`.
6. Adversary C presents a chain C' that is one block longer than the canonical chain but would be outweighed by the canonical chain's Peras boost under correct operation.
7. Node A, applying only chain-length comparison (no Peras weight), selects C' as its preferred chain — diverging from the canonical selection that a correctly-operating node would make.

### Citations

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L139-142)
```haskell
  ( objectDiffusionInboundPeerPipelined
  )
import Ouroboros.Network.Protocol.ObjectDiffusion.Outbound
  ( objectDiffusionOutboundPeer
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L199-201)
```haskell
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
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
