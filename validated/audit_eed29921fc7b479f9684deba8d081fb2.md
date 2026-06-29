After thorough code analysis of the NEAR Omni Bridge codebase, I have completed my validation.

---

Audit Report

## Title
Missing Token Registration Check in `ft_on_transfer`/`init_transfer` Allows Permanent Freezing of Unregistered Tokens - (File: near/omni-bridge/src/lib.rs)

## Summary
The `ft_on_transfer` entry point and the `init_transfer` / `init_transfer_internal` functions accept any NEP-141 token without verifying that the token is registered in the bridge (i.e., present in `token_id_to_address`). When a token whose metadata has been logged (via `log_metadata`) but not yet deployed/bound (via `deploy_token` / `bind_token`) is sent to the bridge, the bridge permanently retains the tokens while every subsequent `sign_transfer` call panics with `FailedToGetTokenAddress`. There is no built-in cancel or recovery path.

## Finding Description

**Root cause — no registration guard in the inbound token path:**

`ft_on_transfer` (line 253) derives `token_id` from `env::predecessor_account_id()` and immediately dispatches to `init_transfer` (line 263) without any check that the token is present in `token_id_to_address` or `deployed_tokens`.

`init_transfer` (lines 523–619) builds a `TransferMessage` and calls `init_transfer_internal` without any registration check.

`init_transfer_internal` (lines 1829–1865):
1. Calls `add_transfer_message` — stores the pending transfer unconditionally.
2. Calls `try_update_storage_balance` — succeeds if the user has pre-deposited storage.
3. Enters the `OmniAddress::Near` branch (always true for NEAR-side tokens).
4. Calls `burn_tokens_if_needed` — no-op because `is_deployed_token` returns `false` for an unregistered token.
5. Calls `lock_tokens_if_needed` — no-op because no entry exists in `locked_tokens`.
6. **Returns `U128(0)`** — the NEP-141 standard interprets this as "keep all tokens"; the bridge now holds the user's funds.

The transfer message is now stored in `pending_transfers`. When a relayer (or the user) calls `sign_transfer`, it executes:

```rust
let token_address = self
    .get_token_address(
        transfer_message.get_destination_chain(),
        self.get_token_id(&transfer_message.token),
    )
    .unwrap_or_else(|| {
        env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
    });
```

`get_token_id` for an `OmniAddress::Near` simply returns the account ID (line 1369–1371). `get_token_address` then looks up `token_id_to_address` for the destination chain (line 1364–1366). For an unregistered token this returns `None`, causing an unconditional panic. `sign_transfer` can never succeed.

**No recovery path exists.** `remove_transfer_message` is only called from `sign_transfer_callback` (on successful signing) and `claim_fee_callback`. Neither is reachable for an unregistered token. There is no `cancel_transfer` or admin rescue function.

**Metadata binding confusion vector:** The `log_metadata` flow (lines 316–384) produces an MPC-signed metadata payload and emits a `LogMetadataEvent`. This is a prerequisite for deploying the token on a foreign chain, but it does **not** register the token in the bridge. Registration only happens after `deploy_token` (lines 1136–1175) or `bind_token` (lines 1223–1301) completes successfully. A user who has completed `log_metadata` but not yet `bind_token`/`deploy_token` may reasonably believe their token is bridge-ready and initiate a transfer, permanently freezing their funds.

## Impact Explanation
Permanent freezing of bridged funds on NEAR. The user's NEP-141 tokens are transferred into the bridge contract and cannot be recovered through any on-chain mechanism. This matches the Critical impact class: *"permanent freezing of bridged funds across NEAR … flows."*

## Likelihood Explanation
Any unprivileged token holder can trigger this by calling `ft_transfer_call` on any NEP-141 token contract, directing it to the bridge with a valid `InitTransfer` JSON message. The only precondition is that the user has a storage deposit in the bridge (a normal operational requirement). The scenario is realistic for any token that has completed `log_metadata` but not yet `bind_token`/`deploy_token`, which is a normal intermediate state during token onboarding.

## Recommendation
Add a registration guard at the start of `init_transfer` (or inside `init_transfer_internal` before returning `U128(0)`):

```rust
require!(
    self.token_id_to_address
        .get(&(init_transfer_msg.get_destination_chain(), token_id.clone()))
        .is_some(),
    BridgeError::TokenNotRegistered.as_ref()
);
```

Returning the full `transfer_message.amount` (refund) instead of `U128(0)` when the token is not registered would also be sufficient to prevent fund loss, but the explicit guard is cleaner and fails fast before storage is consumed.

## Proof of Concept
**Minimal local unit-test sequence (near-workspaces / sandbox):**

1. Deploy a fresh NEP-141 token contract (`my-token.testnet`) that is **not** registered in the bridge.
2. Call `log_metadata` on the bridge for `my-token.testnet` (optional — demonstrates the metadata-logged-but-not-bound state).
3. Pre-deposit storage for the test account via `storage_deposit`.
4. Call `ft_transfer_call` on `my-token.testnet`:
   - `receiver_id`: bridge contract
   - `amount`: 1000
   - `msg`: `{"InitTransfer":{"recipient":"eth:0xDEAD...","fee":"0","native_token_fee":"0"}}`
5. Assert the bridge's token balance of `my-token.testnet` increased by 1000 (tokens kept).
6. Call `sign_transfer` with the resulting `TransferId`.
7. Assert the call panics with `FailedToGetTokenAddress`.
8. Assert there is no mechanism to retrieve the 1000 tokens.