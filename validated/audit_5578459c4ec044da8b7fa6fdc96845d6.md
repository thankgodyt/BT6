### Title
`denormalize_amount` Multiplication Overflow Permanently Freezes Bridged Funds on Source Chain - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `denormalize_amount` helper in the NEAR bridge contract performs an unchecked `u128` multiplication. Because the workspace compiles with `overflow-checks = true`, any overflow panics the transaction. A user who initiates a cross-chain transfer with a sufficiently large token amount causes `fin_transfer_callback` to panic after the source-chain tokens are already locked/burned, permanently freezing those funds until a contract upgrade is deployed.

### Finding Description
`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // unchecked multiplication
}
``` [1](#0-0) 

The workspace `[profile.release]` section explicitly sets `overflow-checks = true`: [2](#0-1) 

Under this setting, Rust inserts a runtime overflow check on every integer arithmetic operation. If `amount * 10^diff_decimals` exceeds `u128::MAX`, the runtime panics.

`denormalize_amount` is called unconditionally inside `fin_transfer_callback` before any state mutation that would mark the transfer as finalised:

```rust
let transfer_message = TransferMessage {
    ...
    amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
    fee:    Self::denormalize_fee(&init_transfer.fee, decimals),
    ...
};
``` [3](#0-2) 

`add_fin_transfer` (which inserts into `finalised_transfers`) is only called later, inside `process_fin_transfer_to_near` or `process_fin_transfer_to_other_chain`: [4](#0-3) 

Because the panic occurs before `add_fin_transfer`, the transfer ID is **never** recorded as finalised. However, the source-chain transaction (EVM `initTransfer`) has already been mined and the tokens locked or burned. The proof cannot be resubmitted until a contract upgrade is deployed and approved by the DAO.

The same unchecked call appears in `fast_fin_transfer` and `claim_fee_callback`: [5](#0-4) [6](#0-5) 

### Impact Explanation
The overflow threshold (in whole source-chain tokens) is approximately `u128::MAX / 10^diff_decimals / 10^evm_decimals`. For a token with 18 EVM decimals and 24 NEAR decimals (`diff_decimals = 6`), the threshold is roughly **340 trillion whole tokens**. Tokens such as SHIB (~589 trillion supply) or PEPE (~420 trillion supply) exceed this threshold. Any holder of more than ~340 trillion such tokens who bridges their full balance will have those tokens permanently locked on EVM while the NEAR callback panics and the transfer is never finalised. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation
The attacker-controlled input is the `amount` field of the EVM `InitTransfer` event, which is a `uint128` set by the user when calling `initTransfer`. No privileged role is required. Any bridge user holding a sufficiently large balance of a high-supply token (a realistic condition for meme tokens) can trigger this path, either accidentally or deliberately. The relayer submitting the proof is acting correctly; the overflow is entirely a function of the user-supplied amount and the registered decimal configuration.

### Recommendation
Replace the bare multiplication in `denormalize_amount` with a checked variant that returns an error instead of panicking:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> Result<u128, BridgeError> {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    let multiplier = 10_u128.pow(diff_decimals);
    amount.checked_mul(multiplier).ok_or(BridgeError::AmountOverflow)
}
```

Propagate the error in `fin_transfer_callback`, `fast_fin_transfer`, and `claim_fee_callback` so that an oversized amount causes a clean, recoverable rejection rather than a panic. This prevents the source-chain tokens from being locked without a corresponding NEAR-side record.

### Proof of Concept
Consider a token registered with `decimals = 18` (EVM) and `origin_decimals = 24` (NEAR), giving `diff_decimals = 6`.

1. User holds `4 × 10^32` EVM token units (≈ 400 trillion whole tokens, within SHIB-class supply).
2. User calls `initTransfer` on the EVM bridge with `amount = 4 × 10^32`. EVM bridge burns those tokens and emits `InitTransfer`.
3. Relayer submits the proof to the NEAR bridge via `fin_transfer`.
4. `fin_transfer_callback` executes:
   - `denormalize_amount(4e32, Decimals { decimals: 18, origin_decimals: 24 })`
   - `= 4e32 * 10^6 = 4e38`
   - `u128::MAX ≈ 3.4e38 < 4e38` → **overflow panic**
5. The NEAR callback reverts. `finalised_transfers` is not updated.
6. The EVM burn is irreversible. The user's `4 × 10^32` tokens are permanently lost until a DAO-approved contract upgrade is deployed. [1](#0-0) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L770-772)
```rust
        let denormalized_amount =
            Self::denormalize_amount(fast_fin_transfer_msg.amount.0, decimals);
        let denormalized_fee = Self::denormalize_fee(&fast_fin_transfer_msg.fee, decimals);
```

**File:** near/omni-bridge/src/lib.rs (L1122-1127)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
```

**File:** near/omni-bridge/src/lib.rs (L1875-1875)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/Cargo.toml (L24-31)
```text
[profile.release]
codegen-units = 1
# Tell `rustc` to optimize for small code size.
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```
