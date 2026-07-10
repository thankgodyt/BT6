### Title
Bitcoin Refund Gas Fee Locked at Request Time Causes Stuck Refunds and User Overcharging - (File: `contracts/satoshi-bridge/src/bitcoin_utils/refund.rs`)

### Summary
The default Bitcoin refund `gas_fee` is resolved once at `request_refund` time to `max_btc_gas_fee` (the configured maximum) and permanently stored in the `RefundRequest`. This locked fee cannot be updated for existing requests. If Bitcoin network fees spike above this locked value during the mandatory timelock window (2–14 days), the resulting refund transaction cannot confirm on-chain. Because `max_gas_fee` in `BTCPendingInfo` is set to the same locked value, RBF cannot raise the fee further. Once `execute_refund` is called, the deposit UTXO is inserted into `verified_deposit_utxo`, blocking any new `request_refund` for the same UTXO. The user's BTC is then stuck with no on-chain recovery path.

### Finding Description

**Root cause — fee locked at request time, not execution time:**

In `contracts/satoshi-bridge/src/bitcoin_utils/refund.rs`, the default fee for Bitcoin refunds is always the configured maximum:

```rust
pub(crate) fn get_refund_gas_fee(&self) -> u128 {
    self.internal_config().max_btc_gas_fee   // always the ceiling
}
``` [1](#0-0) 

In `request_refund_callback`, this value is resolved once and written into the `RefundRequest`:

```rust
let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
// ...
gas_fee: resolved_gas_fee,
``` [2](#0-1) 

The stored `gas_fee` is then used verbatim at `execute_refund` time to compute `refund_amount = deposit_amount - gas_fee`: [3](#0-2) 

**RBF ceiling equals the locked fee:**

`finalize_refund_with_psbt` sets `max_gas_fee` in `BTCPendingInfo` to the same locked value:

```rust
state: PendingInfoState::Refund(OriginalState {
    stage: PendingInfoStage::PendingSign,
    max_gas_fee: gas_fee,   // ceiling == initial fee → no RBF headroom
    ...
}),
``` [4](#0-3) 

**UTXO permanently blocked after `execute_refund`:**

`execute_refund` inserts the deposit UTXO into `verified_deposit_utxo`: [5](#0-4) 

`request_refund_callback` rejects any new refund request for a UTXO already in that set: [6](#0-5) 

So once `execute_refund` fires with an under-priced fee, the user cannot create a new refund request with a higher fee. The only escape would require DAO/Operator to reject the request — but rejection does not remove the UTXO from `verified_deposit_utxo`, so the user still cannot re-request.

**Overcharging in the normal case:**

Even when Bitcoin fees are low, every unprivileged user pays `max_btc_gas_fee` (the ceiling), not the actual market rate. This is the direct analog of the Linea report's finding that L1 V1 users were overcharged by ~20% because `REFUND_OVERHEAD_IN_GAS` was set too high relative to actual gas costs. [7](#0-6) 

The configurable timelock window during which the fee rate can diverge from the locked value: [8](#0-7) 

### Impact Explanation
**Low.** When Bitcoin network fees spike above `max_btc_gas_fee` during the 2–14 day timelock window, the refund transaction cannot confirm and cannot be RBF'd. After `execute_refund` is called, the deposit UTXO is permanently blocked in `verified_deposit_utxo`, leaving the user's BTC in a stuck state with no self-service recovery path. In the normal (non-spike) case, users are systematically overcharged because the default fee is always the configured maximum regardless of actual network conditions.

### Likelihood Explanation
**Low.** Bitcoin fee spikes above a well-configured `max_btc_gas_fee` are infrequent but historically documented (e.g., Ordinals inscription waves, halving periods). The 2–14 day timelock window meaningfully increases exposure. The overcharging case occurs on every unprivileged refund request regardless of network conditions.

### Recommendation
1. **Decouple fee estimation from request time.** Resolve the actual Bitcoin fee at `execute_refund` time (when the PSBT is built and the fee rate is known), not at `request_refund` time.
2. **Allow RBF headroom.** Set `max_gas_fee` in `BTCPendingInfo` to a value higher than the initial fee (e.g., `config.max_btc_gas_fee`) so that RBF can increase the fee if the initial estimate proves insufficient.
3. **Add a fee-update path.** Allow DAO/Operator to update the `gas_fee` of an existing `RefundRequest` before `execute_refund` is called, analogous to the Linea team's recommendation to make the refund overhead configurable over time.
4. **Use a fee-rate oracle or sliding scale.** Rather than always defaulting to `max_btc_gas_fee`, derive the default from a recent fee-rate estimate (e.g., from the light client or a configurable `sat/vbyte` parameter) to avoid systematic overcharging.

### Proof of Concept

1. Alice deposits 100,000 sats to a bridge deposit address with `refund_address` set.
2. Alice calls `request_refund` with `gas_fee = None`. The contract stores `gas_fee = max_btc_gas_fee` (e.g., 50,000 sats) in the `RefundRequest`.
3. Bitcoin fees spike to 80,000 sats for a 1-in/1-out transaction during the 2-day timelock.
4. After the timelock, Alice (or anyone) calls `execute_refund`. The contract:
   - Builds a PSBT: input = 100,000 sats, output = 50,000 sats, fee = 50,000 sats.
   - Inserts the UTXO into `verified_deposit_utxo`.
   - Creates `BTCPendingInfo` with `max_gas_fee = 50,000 sats`.
5. The refund transaction is broadcast but never confirms (80,000 sats required, only 50,000 offered).
6. RBF cannot increase the fee beyond 50,000 sats (`max_gas_fee` ceiling).
7. Alice cannot call `request_refund` again (UTXO is in `verified_deposit_utxo`).
8. Alice's 100,000 sats are stuck with no self-service recovery.

### Citations

**File:** contracts/satoshi-bridge/src/bitcoin_utils/refund.rs (L10-12)
```rust
    pub(crate) fn get_refund_gas_fee(&self) -> u128 {
        self.internal_config().max_btc_gas_fee
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L280-284)
```rust
        let refund_amount = refund_request
            .amount
            .checked_sub(refund_request.gas_fee)
            .expect("Deposit amount too small to cover gas fee");
        require!(refund_amount > 0, "Refund amount is zero after gas fee");
```

**File:** contracts/satoshi-bridge/src/refund.rs (L358-363)
```rust
            state: PendingInfoState::Refund(OriginalState {
                stage: PendingInfoStage::PendingSign,
                max_gas_fee: gas_fee,
                last_rbf_time_sec: None,
                cancel_rbf_reserved: None,
            }),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L377-380)
```rust
        // Mark UTXO as verified to prevent verify_deposit later
        self.data_mut()
            .verified_deposit_utxo
            .insert(utxo_storage_key.clone());
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-572)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );

        Event::RefundRequested {
            deposit_msg: deposit_msg.clone(),
            utxo_storage_key: utxo_storage_key.clone(),
            amount: amount.into(),
            refund_address: refund_address.clone(),
            gas_fee: resolved_gas_fee.into(),
        }
        .emit();

        let refund_request = RefundRequest {
            deposit_msg_json: serde_json::to_string(&deposit_msg).unwrap(),
            utxo_storage_key: utxo_storage_key.clone(),
            tx_bytes,
            vout,
            amount,
            refund_address,
            gas_fee: resolved_gas_fee,
            created_at_sec: nano_to_sec(env::block_timestamp()),
```

**File:** contracts/satoshi-bridge/src/config.rs (L8-9)
```rust
pub const DEFAULT_REFUND_TIMELOCK_SEC: u64 = 2 * 24 * 3600;
pub const DEFAULT_UNSAFE_REFUND_TIMELOCK_SEC: u64 = 14 * 24 * 3600;
```

**File:** contracts/satoshi-bridge/src/config.rs (L83-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```
