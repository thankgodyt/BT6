Audit Report

## Title
Failed `fin_transfer` Removes Replay Guard, Enabling Proof Replay and Double-Minting — (File: near/omni-bridge/src/lib.rs)

## Summary
When a `fin_transfer` to a NEAR recipient fails because the recipient's `ft_on_transfer` rejects the tokens (returning 0 used), `fin_transfer_send_tokens_callback` calls `remove_fin_transfer`, which deletes the `TransferId` from `finalised_transfers`. This permanently erases the only replay guard for that source-chain event, allowing the identical proof to be submitted again by any trusted relayer. A single on-chain `InitTransfer` event on the source chain can therefore cause multiple NEAR-side token mints or unlocks.

## Finding Description
The NEAR omni-bridge uses `finalised_transfers: LookupSet<TransferId>` as its sole replay-protection store for inbound transfers destined for NEAR. The `TransferId` is `(origin_chain, origin_nonce)`, derived directly from the source-chain event.

**Step 1 — Replay guard is set:**
`process_fin_transfer_to_near` calls `add_fin_transfer`, which inserts the `TransferId` and panics if it already exists:
```rust
// lib.rs:1875
let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```
```rust
// lib.rs:2228-2230
require!(
    self.finalised_transfers.insert(transfer_id),
    BridgeError::TransferAlreadyFinalised.as_ref()
);
```

**Step 2 — Token delivery is attempted via `ft_transfer_call`:**
When the transfer message carries a non-empty `msg`, `send_tokens` issues an `ft_transfer_call` (or `mint` with a message for deployed tokens). The result is inspected in `is_refund_required`:
```rust
// lib.rs:1784-1791
fn is_refund_required(is_ft_transfer_call: bool) -> bool {
    if is_ft_transfer_call {
        match env::promise_result_checked(0, MAX_FT_TRANSFER_CALL_RESULT) {
            Ok(value) => {
                if let Ok(amount) = near_sdk::serde_json::from_slice::<U128>(&value) {
                    amount.0 == 0  // refund if recipient consumed no tokens
```

**Step 3 — On failure, the replay guard is deleted:**
If `is_refund_required` returns `true`, `fin_transfer_send_tokens_callback` burns the minted tokens, reverts lock actions, and then calls `remove_fin_transfer`, which removes the `TransferId` from `finalised_transfers`:
```rust
// lib.rs:1702-1714
if Self::is_refund_required(is_ft_transfer_call) {
    self.burn_tokens_if_needed(...);
    self.revert_lock_actions(&lock_actions);
    self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);
```
```rust
// lib.rs:2322-2324
fn remove_fin_transfer(&mut self, transfer_id: &TransferId, storage_owner: &AccountId) {
    let storage_usage = env::storage_usage();
    self.finalised_transfers.remove(transfer_id);
```

**Step 4 — The same proof is now replayable:**
Because `finalised_transfers` no longer contains the `TransferId`, a subsequent call to `fin_transfer` with the identical Borsh-encoded proof passes `add_fin_transfer` without reverting. For NEAR-destined transfers, `get_next_destination_nonce` always returns 0, providing no additional protection:
```rust
// lib.rs:1815-1817
fn get_next_destination_nonce(&mut self, chain_kind: ChainKind) -> Nonce {
    if chain_kind == ChainKind::Near {
        return 0;
```
The bridge then mints or unlocks tokens a second time from the same source-chain proof.

**Why existing checks fail:**
The `add_fin_transfer` guard is the only replay check for NEAR-destined transfers. Once `remove_fin_transfer` deletes the entry, the guard is gone permanently. There is no secondary nonce, no `failed_transfers` map, and no other mechanism to prevent re-submission of the same proof.

## Impact Explanation
A single source-chain `InitTransfer` event (which locked or burned tokens exactly once on the origin chain) can cause the NEAR bridge to mint or unlock the same token amount multiple times. For deployed (bridged) tokens, this constitutes unauthorized minting — new tokens are created on NEAR without any corresponding lock on the source chain, directly breaking the 1:1 backing invariant. For non-deployed (escrowed) tokens, `revert_lock_actions` re-locks the tokens after the first failure, and the replay unlocks them again, constituting escrow mis-accounting and double-spending. Both outcomes result in unbacked tokens circulating on NEAR and direct loss of funds for the protocol. This matches the critical impact class: "unauthorized minting" and "nonce/replay misuse... enabling invalid finalization or double-spending."

## Likelihood Explanation
`fin_transfer` is gated by `#[trusted_relayer]`, restricting callers to accounts that have staked 1000 NEAR and passed the activation waiting period (subject to DAO rejection). This is an open but permissioned role — any external party can apply. Critically, the exploit does **not** require a malicious relayer: a legitimate relayer retrying a failed transfer after the recipient's conditions change (e.g., a DEX router or vault that was at capacity and later drained) is the natural, non-malicious trigger path. The `FailedFinTransferEvent` log emitted at line 1716-1718 even signals to off-chain relayer infrastructure that a retry may be appropriate, making accidental double-minting a realistic operational scenario. The trigger condition — a recipient contract whose `ft_on_transfer` transiently rejects tokens — is realistic for any contract with conditional acceptance logic.

## Recommendation
Do **not** remove the `TransferId` from `finalised_transfers` on failure. The replay guard must be permanent regardless of whether the downstream token delivery succeeded. If a retry with different `storage_deposit_actions` is desired, track the failure state separately (e.g., a `failed_transfers: LookupMap<TransferId, FailedTransferState>`) and allow the relayer to re-attempt delivery without re-verifying the proof. The re-attempt path would skip `add_fin_transfer` (since the entry already exists and is marked failed) and proceed directly to `send_tokens`. This mirrors the standard fix: the finalization record must survive failed executions.

## Proof of Concept
1. Alice initiates a transfer of 10,000 USDC from Ethereum to a NEAR recipient contract `receiver.near` that implements `ft_on_transfer` with a capacity check (rejects when its internal balance exceeds a threshold).
2. Relayer calls `fin_transfer` with the valid EVM proof. `add_fin_transfer` inserts `TransferId{Eth, nonce=42}` into `finalised_transfers`. The bridge mints 10,000 USDC and calls `ft_transfer_call` → `receiver.near::ft_on_transfer` → rejects (capacity full), returns full amount unused (0 used).
3. `is_refund_required` returns `true`. `fin_transfer_send_tokens_callback` burns the minted tokens and calls `remove_fin_transfer`, deleting `TransferId{Eth, nonce=42}` from `finalised_transfers`.
4. `receiver.near` drains its balance (capacity now available).
5. Relayer (acting in good faith, retrying the failed transfer) resubmits the identical proof. `add_fin_transfer` succeeds (entry was deleted). Bridge mints another 10,000 USDC and delivers them to `receiver.near`.
6. Result: 20,000 USDC minted on NEAR from a single 10,000 USDC lock on Ethereum. The bridge is 10,000 USDC under-collateralised.

**Minimal integration test plan:**
- Deploy the bridge contract and a mock token contract (deployed/bridged token).
- Deploy a mock receiver contract whose `ft_on_transfer` returns the full amount (simulating rejection) on the first call and `0` (acceptance) on the second call.
- Call `fin_transfer` with a valid proof for `TransferId{Eth, nonce=1}` targeting the mock receiver. Verify `FailedFinTransferEvent` is emitted and the `TransferId` is absent from `finalised_transfers`.
- Call `fin_transfer` again with the identical proof. Assert it succeeds (no `TransferAlreadyFinalised` panic) and that the receiver's token balance equals the transfer amount — demonstrating double-minting from a single source-chain event.