### Title
Unchecked Multiplication Overflow in `denormalize_amount` Causes Permanent Loss of Bridged Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

`denormalize_amount` performs a raw, unchecked `u128` multiplication to scale a normalized token amount back to its origin-chain representation. When a user bridges a sufficiently large amount from a foreign chain (EVM, Solana, etc.) to NEAR, this multiplication overflows, causing either a silent wrap-around (wrong amount credited) or a panic (transfer permanently fails while tokens remain locked on the source chain).

### Finding Description

`denormalize_amount` is defined as:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The raw `*` operator on `u128` has no overflow guard. In Rust release builds (the standard for NEAR contracts), integer overflow either wraps silently or panics depending on whether `overflow-checks` is set. Neither outcome is safe.

`denormalize_amount` is called inside `fin_transfer_callback` — the publicly reachable inbound-transfer finalisation path — with the raw amount parsed directly from the prover result:

```rust
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [2](#0-1) 

It is also called on the fee field via `denormalize_fee`:

```rust
fee: Self::denormalize_fee(&init_transfer.fee, decimals),
``` [3](#0-2) 

The `Decimals` struct for a token registered via `bind_token` stores `decimals` (the normalized, destination-chain precision) and `origin_decimals` (the source-chain precision):

```rust
self.add_token(
    &deploy_token.token,
    &deploy_token.token_address,
    deploy_token.decimals,
    deploy_token.origin_decimals,
);
``` [4](#0-3) 

For a NEAR-origin token bridged to EVM (18 EVM decimals, 24 NEAR decimals), `diff_decimals = 6` and the multiplier is `10^6`. The overflow threshold is:

```
u128::MAX / 10^6  ≈  3.4 × 10^32
```

A user who sends more than `3.4 × 10^32` raw EVM units (≈ 340 trillion tokens at 18 decimals) triggers the overflow. For tokens with large supplies and low per-unit value this is a realistic amount. The EVM `initTransfer` accepts `uint128 amount`, so the full range up to `u128::MAX` is user-controllable. [5](#0-4) 

### Impact Explanation

Two failure modes, both critical:

1. **Overflow-checks disabled (wrapping):** `denormalize_amount` silently returns a value far smaller than the true amount. The user's tokens are permanently locked/burned on the source chain while they receive a tiny fraction on NEAR. Funds are irreversibly lost.

2. **Overflow-checks enabled (panic):** `fin_transfer_callback` panics. NEAR reverts the callback's state changes, but the source-chain lock/burn has already been finalised and cannot be undone. The user's tokens are permanently frozen in the source-chain bridge contract with no recovery path.

Both outcomes constitute permanent, irreversible loss of bridged funds for the affected user.

### Likelihood Explanation

The overflow threshold is high (hundreds of trillions of raw token units), making it unlikely for high-value tokens. However:

- Any token with a large total supply and low per-unit value (e.g., meme tokens, reward tokens) can reach this threshold with a single transfer.
- The EVM `initTransfer` interface accepts the full `uint128` range with no upper-bound check.
- No special privilege is required — any bridge user can trigger this path by calling `initTransfer` on the EVM contract with a sufficiently large amount.

### Recommendation

Replace the raw multiplication in `denormalize_amount` (and the subtraction `origin_decimals - decimals`) with checked arithmetic that panics with a clear error message before any state is mutated:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = decimals.origin_decimals
        .checked_sub(decimals.decimals)
        .expect("origin_decimals must be >= decimals")
        .into();
    let multiplier = 10_u128.checked_pow(diff_decimals)
        .expect("decimal multiplier overflow");
    amount.checked_mul(multiplier)
        .expect("denormalize_amount overflow")
}
```

Apply the same pattern to `denormalize_fee`, which delegates to `denormalize_amount`. [6](#0-5) 

### Proof of Concept

1. Register a NEAR-origin token on EVM via `bind_token`. The stored `Decimals` will be `{ decimals: 18, origin_decimals: 24 }`, giving `diff_decimals = 6`.
2. On EVM, call `initTransfer(tokenAddress, amount=3.5e32, fee=0, ...)` where `3.5e32 > u128::MAX / 1e6`.
3. A relayer submits the proof to NEAR `fin_transfer`.
4. `fin_transfer_callback` calls `denormalize_amount(3.5e32, { decimals:18, origin_decimals:24 })`.
5. `3.5e32 * 10^6` overflows `u128`. In wrapping mode the result is a tiny number; in checked mode the callback panics.
6. In either case the user's EVM tokens are permanently lost. [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L700-732)
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
```

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/lib.rs (L2790-2795)
```rust
    fn denormalize_fee(fee: &Fee, decimals: Decimals) -> Fee {
        Fee {
            fee: U128(Self::denormalize_amount(fee.fee.0, decimals)),
            native_fee: fee.native_fee,
        }
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-376)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
```
