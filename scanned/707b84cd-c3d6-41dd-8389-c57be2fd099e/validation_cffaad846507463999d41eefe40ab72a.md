### Title
Permanent Fund Freezing Due to Missing Normalized-Amount Validation in `init_transfer` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

A user can initiate a cross-chain transfer with an amount that passes the only validation gate in `init_transfer` (fee < amount) but normalizes to zero in `sign_transfer` due to decimal-precision conversion between chains. Once the transfer is stored in `pending_transfers`, no relayer or DAO call can ever complete it — `sign_transfer` always reverts — and no cancel/refund path exists, permanently locking the deposited tokens inside the bridge contract.

---

### Finding Description

**Root cause — missing pre-flight normalization check in `init_transfer`:**

`init_transfer` validates only that the fee is less than the amount: [1](#0-0) 

It does not verify that the amount, after decimal normalization to the destination chain's precision, is still greater than zero. The tokens are immediately transferred to the bridge and the `TransferMessage` is written to `pending_transfers`.

**Blocking check in `sign_transfer`:**

When a relayer later calls `sign_transfer`, the amount is normalized to the destination chain's decimal precision using the `Decimals` struct (which carries both `decimals` and `origin_decimals`): [2](#0-1) 

If the destination chain has fewer decimals than NEAR (e.g., a token represented with 18 decimals on NEAR but 6 on Ethereum), and the user's `amount_without_fee` is smaller than `10^(18-6) = 10^12`, integer division in `normalize_amount` yields 0. The `require!(amount_to_transfer > 0, BridgeError::InvalidAmountToTransfer)` guard then always panics, making `sign_transfer` permanently revert for this specific transfer.

**No recovery path:**

`sign_transfer_callback` only removes the transfer from `pending_transfers` when the MPC signing call succeeds: [3](#0-2) 

Because `sign_transfer` panics before the MPC call is ever dispatched, the callback is never reached, and the transfer record is never cleaned up. No `cancel_transfer`, `withdraw_transfer`, or equivalent refund function is present in the contract.

The `Decimals` storage type that drives this normalization: [4](#0-3) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.** The user's NEP-141 tokens are transferred to the bridge contract during `ft_on_transfer` → `init_transfer`. They are recorded in `pending_transfers` and can never be recovered: every call to `sign_transfer` for that transfer ID reverts unconditionally, and no alternative exit path exists. The funds are irrecoverably locked on NEAR.

---

### Likelihood Explanation

**Medium.** The conditions are:

1. A token whose NEAR-side representation has significantly more decimals than its destination-chain representation (e.g., USDC/USDT with 18 decimals on NEAR, 6 on Ethereum — a 10^12 divisor).
2. A user sending an amount smaller than the minimum representable unit on the destination chain (e.g., fewer than 10^12 NEAR-side units, which is less than 1 micro-USDC equivalent).

Both conditions are realistic and require no admin action or privileged access. A user can trigger this unilaterally by calling `ft_transfer_call` with a small amount.

---

### Recommendation

Add a normalized-amount check inside `init_transfer` (or at the point where decimals are first available) before accepting the deposit:

```rust
let normalized = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
```

Alternatively, introduce a `cancel_transfer` / refund function that allows the original sender to reclaim tokens from a stuck `pending_transfers` entry.

---

### Proof of Concept

1. Token X is registered with 18 NEAR-side decimals and 6 Ethereum-side decimals (`origin_decimals = 6`, `decimals = 18` in the `Decimals` struct).
2. User calls `ft_transfer_call` on Token X with `amount = 999_999_999_999` (just under `10^12`) and `fee = 0`.
3. `init_transfer` stores the transfer: fee check `0 < 999_999_999_999` passes. Tokens are now held by the bridge.
4. Relayer calls `sign_transfer` for this `transfer_id`.
5. `normalize_amount(999_999_999_999, decimals)` performs integer division: `999_999_999_999 / 10^12 = 0`.
6. `require!(0 > 0, BridgeError::InvalidAmountToTransfer)` panics — `sign_transfer` reverts.
7. No MPC call is made; `sign_transfer_callback` is never invoked; the transfer record remains in `pending_transfers`.
8. The user's `999_999_999_999` Token X units are permanently locked in the bridge with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L471-485)
```rust
        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-557)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L649-668)
```rust
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/storage.rs (L131-136)
```rust
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
