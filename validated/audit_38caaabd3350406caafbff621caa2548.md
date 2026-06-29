Audit Report

## Title
Fast-Transfer-to-NEAR Callback Records State After Cross-Contract Call, Enabling Double-Spending via Race with `fin_transfer` — (File: `near/omni-bridge/src/lib.rs`)

## Summary

In the NEAR Omni Bridge's fast transfer flow for NEAR-address recipients, `add_fast_transfer` is deferred to the asynchronous `fast_fin_transfer_to_near_callback` rather than executed synchronously in `fast_fin_transfer`. During the multi-block window between these two receipts, `fin_transfer` can be called with a valid proof, find no fast transfer entry, and pay the original recipient. When the deferred callback subsequently executes, `add_fast_transfer` succeeds because it only checks for a duplicate key in `fast_transfers` — not in `finalised_transfers` — and the relayer's fronted tokens are sent to the recipient a second time.

## Finding Description

**`fast_fin_transfer` (NEAR recipient branch, lines 778–827):**

The only synchronous guard is `is_unified_transfer_finalised` at line 778, which checks `finalised_transfers` and `finalised_utxo_transfers`. No entry is written to `fast_transfers` at this point. For a NEAR recipient the function issues a cross-contract call to `check_or_pay_ft_storage` and chains `fast_fin_transfer_to_near_callback` as a subsequent receipt (lines 812–827). The non-NEAR branch (`fast_fin_transfer_to_other_chain`, line 914) calls `add_fast_transfer` synchronously at line 941, so the race does not exist there.

**`fast_fin_transfer_to_near_callback` (lines 838–893):**

`add_fast_transfer` is called at line 854–856. There is no guard against `is_unified_transfer_finalised` before this call. The callback then calls `send_tokens` at line 877 to transfer the relayer's fronted tokens to the recipient.

**`process_fin_transfer_to_near` (lines 1875–1902):**

`add_fin_transfer` inserts the transfer ID into `finalised_transfers` at line 1875. `get_fast_transfer_status` is then called at line 1879. If `fast_transfers` has no entry (because the callback has not yet executed), `fast_transfer_status` is `None` and the bridge sends tokens to the original recipient at lines 1897–1901.

**`add_fast_transfer` (lines 2246–2268):**

The only rejection condition is a duplicate key in `fast_transfers` (lines 2253–2264). There is no cross-check against `finalised_transfers`. Because `fin_transfer` never writes to `fast_transfers`, the callback's `add_fast_transfer` call succeeds even after `fin_transfer` has already settled the same transfer.

**Exploit sequence:**

| Step | Actor | Action | State |
|---|---|---|---|
| 1 | Trusted relayer | `ft_transfer_call` → `fast_fin_transfer` (NEAR recipient) | `fast_transfers`: empty; `finalised_transfers`: empty |
| 2 | Any party with proof | `fin_transfer` (valid proof) | `finalised_transfers`: {T}; tokens sent to recipient (1×) |
| 3 | NEAR runtime | `fast_fin_transfer_to_near_callback` executes | `add_fast_transfer` succeeds; relayer's tokens sent to recipient (2×) |

## Impact Explanation

This is a direct double-spend of bridged funds. The recipient receives 2× the bridged amount from a single source-chain transfer: once from `fin_transfer` (minted or unlocked bridge-held tokens) and once from the callback (relayer's fronted tokens). The relayer receives no reimbursement and permanently loses their fronted liquidity. This matches the critical impact class: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."

## Likelihood Explanation

The window spans at least one NEAR block (~1 second) between the `fast_fin_transfer` receipt and the `fast_fin_transfer_to_near_callback` receipt. `fin_transfer` is callable by any party holding a valid proof; the proof is derived from a public source-chain transaction and is available immediately after the source-chain event is finalized. No special privilege beyond holding the proof is required. The attack is deterministic once the relayer's fast-transfer transaction is observed on-chain.

## Recommendation

**Option A (preferred):** In `fast_fin_transfer_to_near_callback`, add a guard before `add_fast_transfer`:

```rust
if self.is_unified_transfer_finalised(&fast_transfer.transfer_id) {
    // fin_transfer already settled; refund relayer's tokens
    return self.send_tokens(fast_transfer.token_id, relayer_id, amount_without_fee, "");
}
```

**Option B:** Move `add_fast_transfer` into `fast_fin_transfer` itself (before the cross-contract call), and revert it in the callback if `check_or_pay_ft_storage` fails. This eliminates the window entirely, consistent with how the non-NEAR branch handles it synchronously at line 941.

## Proof of Concept

1. Source-chain transfer with nonce `N` is initiated; proof `P` is available on-chain.
2. Trusted relayer calls `ft_transfer_call(bridge, amount, FastFinTransferMsg{nonce: N, recipient: Near("alice"), ...})`.
   - `fast_fin_transfer` executes; `is_unified_transfer_finalised` returns false; `fast_transfers` remains empty; `check_or_pay_ft_storage` receipt is queued.
3. In the next block, attacker calls `fin_transfer({proof: P, storage_deposit_actions: [{alice, token}]})`.
   - `add_fin_transfer` inserts `(chain, N)` into `finalised_transfers`.
   - `get_fast_transfer_status` returns `None` → tokens minted/unlocked and sent to `alice` (1×).
4. `fast_fin_transfer_to_near_callback` executes.
   - No `is_unified_transfer_finalised` check present.
   - `add_fast_transfer` succeeds (no entry in `fast_transfers`).
   - `send_tokens` sends relayer's tokens to `alice` (2×).
5. Result: `alice` holds 2× tokens; relayer holds 0 tokens and receives no reimbursement. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L778-780)
```rust
        if self.is_unified_transfer_finalised(&fast_fin_transfer_msg.transfer_id) {
            env::panic_str(BridgeError::TransferAlreadyFinalised.to_string().as_str());
        }
```

**File:** near/omni-bridge/src/lib.rs (L812-827)
```rust
            Self::check_or_pay_ft_storage(
                &deposit_action,
                &mut NearToken::from_yoctonear(storage_deposit_amount),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(
                        FAST_TRANSFER_CALLBACK_GAS.saturating_add(FT_TRANSFER_CALL_GAS),
                    )
                    .fast_fin_transfer_to_near_callback(
                        &fast_transfer,
                        signer_id,
                        fast_fin_transfer_msg.relayer,
                    ),
            )
            .into()
```

**File:** near/omni-bridge/src/lib.rs (L854-856)
```rust
        let required_balance = self
            .add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone())
            .saturating_add(ONE_YOCTO);
```

**File:** near/omni-bridge/src/lib.rs (L877-882)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
```

**File:** near/omni-bridge/src/lib.rs (L940-941)
```rust
        let mut required_balance =
            self.add_fast_transfer(fast_transfer, relayer_id, storage_payer.clone());
```

**File:** near/omni-bridge/src/lib.rs (L1875-1902)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
        let fast_transfer = FastTransfer::from_transfer(transfer_message.clone(), token.clone());
        let fast_transfer_status = self.get_fast_transfer_status(&fast_transfer.id());

        let lock_actions = vec![self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        )];

        // If fast transfer happened, change recipient and fee recipient to the relayer that executed fast transfer
        let (recipient, msg, fee_recipient) = match fast_transfer_status {
            Some(status) => {
                require!(
                    !status.finalised,
                    BridgeError::FastTransferAlreadyFinalised.as_ref()
                );
                self.remove_fast_transfer(&fast_transfer.id());
                (status.relayer.clone(), String::new(), status.relayer)
            }
            None => (
                recipient,
                transfer_message.msg.clone(),
                predecessor_account_id.clone(),
            ),
        };
```

**File:** near/omni-bridge/src/lib.rs (L2246-2268)
```rust
    fn add_fast_transfer(
        &mut self,
        fast_transfer: &FastTransfer,
        relayer: AccountId,
        storage_owner: AccountId,
    ) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.fast_transfers
                .insert(
                    &fast_transfer.id(),
                    &FastTransferStatusStorage::V0(FastTransferStatus {
                        relayer,
                        storage_owner,
                        finalised: false,
                    }),
                )
                .is_none(),
            BridgeError::FastTransferAlreadyPerformed.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
