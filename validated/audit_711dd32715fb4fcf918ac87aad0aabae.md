Audit Report

## Title
Deferred Token-Address Validation in `init_transfer` Permanently Freezes Burned/Locked Funds — (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` commits an irreversible state change — burning or locking the user's tokens and recording the entry in `pending_transfers` — without verifying that the transferred token has a registered address on the destination chain. That check is deferred to `sign_transfer`, which panics with `FailedToGetTokenAddress` if the mapping is absent. Because no public cancellation or withdrawal path exists for stuck pending transfers, the user's funds are permanently frozen.

## Finding Description
The outbound NEAR → foreign-chain flow is two-step.

**Step 1 — `init_transfer` (L523–557):** Only two preconditions are enforced before committing the transfer:
- `recipient.get_chain() != ChainKind::Near`
- `fee.fee < amount`

No check is made that `get_token_address(destination_chain, token_id)` returns `Some(...)`, that `token_decimals` contains an entry for that address, or that the normalized amount is non-zero.

**`init_transfer_internal` (L1829–1865):** Immediately calls `add_transfer_message` (inserts into `pending_transfers`), then calls `burn_tokens_if_needed` / `lock_tokens_if_needed`, and returns `U128(0)` — signalling to the NEP-141 `ft_transfer_call` mechanism that no refund should be issued. The only early-exit paths that return the full amount are a storage-balance failure and a non-Near token address, neither of which covers the missing-binding case.

**Step 2 — `sign_transfer` (L462–485):** This is where the deferred validations live. `get_token_address(destination_chain, token_id).unwrap_or_else(|| env::panic_str(...))` panics with `FailedToGetTokenAddress` if the binding is absent. The transfer remains in `pending_transfers` indefinitely.

**No recovery path:** `remove_transfer_message` (L2194–2211) is called only on a successful MPC signing when the fee is zero. `remove_transfer_message_without_refund` (L2213–2224) is called only on storage-balance failure or non-Near token inside `init_transfer_internal`. A search of the contract confirms there is no public `cancel_transfer`, `withdraw_pending_transfer`, or equivalent function. The `pending_transfers` entry — and the burned/locked tokens — are irrecoverable without a contract upgrade.

## Impact Explanation
This is a **permanent freezing of bridged funds**, which is explicitly listed as a Critical allowed impact. The user's tokens are either burned (for bridge-deployed tokens) or locked in the bridge escrow (for native tokens) with no on-chain mechanism to recover them. The `pending_transfers` entry cannot be removed by any unprivileged call, and the NEP-141 refund window has already closed (because `U128(0)` was returned).

## Likelihood Explanation
The bridge supports many destination chains (Eth, Arb, Base, Bnb, Pol, Sol, Strk, BTC, Zcash, HyperEvm, Abs, Fogo). A token is typically registered on a subset of these chains. Any user who calls `ft_transfer_call` targeting a destination chain for which their token has no binding — whether by mistake, because the binding was removed after the transfer was queued, or because the UI does not surface which chains are supported — will trigger this condition. The `amount_to_transfer == 0` variant (dust sent to a chain with fewer decimals) is an additional reachable path. Both are reachable by any unprivileged user through the public `ft_transfer_call` entry point with no special privileges required.

## Recommendation
Move all three validations that `sign_transfer` relies on into `init_transfer` **before** `init_transfer_internal` is called:

1. Assert `get_token_address(destination_chain, token_id)` returns `Some(...)`.
2. Assert `token_decimals` contains an entry for that address.
3. Assert `normalize_amount(amount - fee, decimals) > 0`.

If any check fails, return the full `amount` from `ft_on_transfer` so the NEP-141 mechanism automatically refunds the user — mirroring the pattern already used for storage-balance failures in `init_transfer_internal`.

Additionally, add a DAO-accessible `cancel_pending_transfer` function as a safety valve for transfers that become permanently uncompletable due to post-queue state changes (e.g., token binding removal), which would unlock/re-mint the tokens and remove the `pending_transfers` entry.

## Proof of Concept
1. Token `foo.near` is registered on `ChainKind::Eth` but **not** on `ChainKind::Sol`.
2. User calls `ft_transfer_call` on `foo.near` with `receiver_id = omni-bridge.near` and `msg` encoding an `InitTransferMsg` whose `recipient` is a Solana address.
3. `init_transfer` passes both checks (recipient chain ≠ Near, fee < amount). No token-address check is performed.
4. `init_transfer_internal` inserts the entry into `pending_transfers`, calls `lock_tokens_if_needed` (tokens locked), and returns `U128(0)` — no refund issued.
5. A trusted relayer calls `sign_transfer` for this `transfer_id`.
6. `get_token_address(ChainKind::Sol, foo.near)` returns `None` → `env::panic_str(BridgeError::FailedToGetTokenAddress)`.
7. The transfer remains in `pending_transfers` forever; the user's tokens remain locked with no recovery path.

A local integration test can reproduce this by: (a) registering `foo.near` only on `ChainKind::Eth`, (b) calling `ft_transfer_call` with a Sol recipient, (c) asserting `U128(0)` is returned and tokens are locked, (d) calling `sign_transfer` and asserting it panics, (e) asserting the `pending_transfers` entry still exists and no public call can remove it.