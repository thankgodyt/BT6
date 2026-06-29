### Title
Small-Amount Transfer Permanently Freezes Locked Tokens Due to Zero-Amount Check in `sign_transfer` - (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates an outbound transfer (NEAR → foreign chain) with an amount that normalizes to zero on the destination chain's decimal scale, the `sign_transfer` function permanently panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. Because tokens are already locked at `init_transfer` time and no cancel/refund path exists for stored pending transfers, the user's funds are permanently frozen in the bridge.

### Finding Description

The outbound transfer flow has two distinct phases:

**Phase 1 — `init_transfer` (tokens locked immediately):**
A user calls `ft_transfer_call` on their token contract, which triggers `ft_on_transfer` → `init_transfer` → `init_transfer_internal`. Inside `init_transfer_internal`, the transfer is stored in `pending_transfers` and the tokens are locked/burned before any amount-validity check against the destination chain's decimal scale. [1](#0-0) 

**Phase 2 — `sign_transfer` (amount normalization check, too late):**
A trusted relayer later calls `sign_transfer`. Here, `normalize_amount` divides the amount by `10^(origin_decimals − decimals)`. If the result is zero, the function panics:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [2](#0-1) 

The normalization itself:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [3](#0-2) 

`sign_transfer` makes no state changes before the panic, so the transfer remains in `pending_transfers` with tokens locked. There is no user-callable `cancel_transfer` or refund function for stored pending transfers. [4](#0-3) 

### Impact Explanation

Any amount satisfying `amount_without_fee < 10^(origin_decimals − decimals)` will normalize to zero. For a NEAR-native token (24 decimals) bridged to an EVM chain (18 decimals), the threshold is `10^6` base units. For tokens with larger decimal gaps (e.g., 24 NEAR decimals → 6 EVM decimals), the threshold is `10^18` base units — a non-trivial amount. Once locked, the tokens cannot be recovered: `sign_transfer` is `#[trusted_relayer]`-gated so the user cannot call it themselves, and every relayer attempt will panic identically. The transfer is permanently stuck. [5](#0-4) 

### Likelihood Explanation

Any user who sends an amount below the decimal-gap threshold triggers this. For tokens with large decimal differences (e.g., 24 vs. 6), the threshold is large enough that accidental triggering is realistic. The `init_transfer` path accepts any non-zero amount with `fee < amount` — there is no minimum-amount guard at lock time. [1](#0-0) 

### Recommendation

Move the `normalize_amount > 0` check to `init_transfer_internal`, **before** tokens are locked. If the normalized amount would be zero, return the full `transfer_message.amount` from `ft_on_transfer` (triggering the NEP-141 refund), exactly as the contract already does when storage balance is insufficient:

```rust
// In init_transfer_internal, before locking tokens:
let normalized = Self::normalize_amount(transfer_message.amount_without_fee()..., decimals);
if normalized == 0 {
    self.remove_transfer_message_without_refund(...);
    return transfer_message.amount; // refund via ft_transfer_call
}
```

Alternatively, add a `cancel_transfer` function callable by the original sender that unlocks/refunds tokens for transfers that have been pending beyond a timeout.

### Proof of Concept

1. Token `T` is registered with `origin_decimals = 24`, `decimals = 6` (diff = 18).
2. User calls `ft_transfer_call` with `amount = 10^17` (less than `10^18` threshold), `fee = 0`.
3. `init_transfer_internal` stores the transfer and locks `10^17` units of `T`.
4. Relayer calls `sign_transfer` for this `transfer_id`.
5. `normalize_amount(10^17, {decimals:6, origin_decimals:24}) = 10^17 / 10^18 = 0`.
6. `require!(0 > 0, ...)` panics — `ERR_INVALID_AMOUNT_TO_TRANSFER`.
7. Transfer remains in `pending_transfers`; tokens remain locked forever.
8. No user-callable recovery path exists. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-521)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

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

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/storage.rs (L132-136)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimals {
    pub decimals: u8,
    pub origin_decimals: u8,
}
```
