Audit Report

## Title
`remove_fin_transfer()` Clears Replay Protection on Failed `ft_transfer_call`, Enabling Inbound Transfer Replay — (File: near/omni-bridge/src/lib.rs)

## Summary
When an inbound `fin_transfer` to a NEAR recipient contract fails because the recipient's `ft_on_transfer` rejects all tokens (causing `ft_transfer_call` to return `0` used), the callback `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which unconditionally deletes the `TransferId` from `finalised_transfers`. Since `finalised_transfers` is the bridge contract's sole replay guard for inbound proofs, the same proof can be re-submitted, causing tokens to be minted or unlocked a second time.

## Finding Description
The NEAR bridge contract uses `finalised_transfers: LookupSet<TransferId>` as its replay guard. In `fin_transfer_send_tokens_callback`, when `is_refund_required` returns `true`, the code path at lines 1702–1714 calls `burn_tokens_if_needed`, `revert_lock_actions`, and then `remove_fin_transfer`, which at lines 2322–2324 calls `self.finalised_transfers.remove(transfer_id)` unconditionally.

`is_refund_required` (lines 1784–1803) returns `true` when `is_ft_transfer_call` is `true` and the promise result from `ft_transfer_call` deserializes to a `U128` with value `0` — meaning zero tokens were used (i.e., the receiver rejected all tokens by returning the full amount from `ft_on_transfer`, or panicked). This is a fully attacker-controlled condition: the `msg` field (which sets `is_ft_transfer_call = true`) is specified by the sender on the foreign chain, and the recipient contract's `ft_on_transfer` behavior is controlled by whoever deploys it.

After `remove_fin_transfer` executes, `add_fin_transfer` (lines 2226–2234) will succeed again for the same `TransferId` because `finalised_transfers.insert` no longer finds a duplicate. The prover is called to verify the cryptographic validity of the proof, but proof-replay tracking is the bridge contract's responsibility via `finalised_transfers`. With that entry gone, the same EVM/Solana/Starknet event proof can be re-submitted and re-finalized.

## Impact Explanation
**Critical — unauthorized minting and double-spend of bridged funds.**

- **Deployed (bridged) tokens:** `burn_tokens_if_needed` burns the rejected tokens on the first attempt. On replay, `fin_transfer` mints a fresh batch from nothing. Repeatable indefinitely, draining the token supply.
- **Native (locked) tokens:** `burn_tokens_if_needed` is a no-op. The NEP-141 refund mechanism returns the tokens to the bridge. On replay, they are transferred out again — a double-spend of locked reserves.

This matches the allowed critical impact: *cross-chain replay / nonce misuse enabling invalid finalization or double-spending* and *unauthorized minting of bridged funds*.

## Likelihood Explanation
**High.** The attacker needs only to:
1. Control a NEAR contract as the designated recipient of a cross-chain transfer.
2. Initiate a transfer from any supported foreign chain with a non-empty `msg` field (fully attacker-controlled at transfer initiation time).
3. Have `ft_on_transfer` return the full token amount (reject all tokens), causing `ft_transfer_call` to return `0`.

No privileged access, key compromise, or external dependency failure is required. Any user who can initiate a cross-chain transfer and deploy a NEAR contract can execute this attack. The attack is repeatable with the same proof.

## Recommendation
Do **not** remove the `TransferId` from `finalised_transfers` on delivery failure. The replay-protection record must be permanent once a valid proof has been accepted. If retry or refund semantics are needed, track the failure state separately (e.g., a `failed_transfers: LookupMap<TransferId, FailureInfo>`) and allow re-delivery attempts or manual refund claims without ever clearing the finalization record. The nonce must never become reusable after a valid proof has been accepted.

## Proof of Concept
1. Attacker deploys `evil.near` whose `ft_on_transfer` always returns the full received amount (rejects all tokens).
2. Attacker initiates a transfer from Ethereum to `evil.near` with a non-empty `msg` field, locking 1000 USDC on the EVM side.
3. Relayer submits the EVM event proof; `fin_transfer` is called, `TransferId{Eth, nonce=42}` is inserted into `finalised_transfers`, and 1000 USDC is minted and sent via `ft_transfer_call` to `evil.near`.
4. `evil.near.ft_on_transfer` returns `1000` (full amount to refund); `ft_transfer_call` returns `U128(0)` (used = 0).
5. `fin_transfer_send_tokens_callback` sees `is_refund_required = true`, calls `burn_tokens_if_needed` (burns 1000 USDC), and calls `remove_fin_transfer`, deleting `TransferId{Eth, nonce=42}` from `finalised_transfers`.
6. Attacker re-submits the same EVM proof. `add_fin_transfer` succeeds (entry absent), 1000 USDC is minted again and sent to `evil.near`.
7. This time `evil.near` accepts the tokens (returns `0`). Attacker holds 1000 USDC despite the original 1000 USDC having been burned — net gain of 1000 USDC from nothing.
8. Steps 3–7 can be repeated with the same proof indefinitely.