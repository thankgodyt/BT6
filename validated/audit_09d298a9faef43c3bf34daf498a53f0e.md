### Title
User Cannot Specify Maximum Gas-Fee Slippage Protection During nBTC Withdrawal — (File: `contracts/satoshi-bridge/src/psbt.rs`)

---

### Summary

When a user initiates a BTC withdrawal by burning nBTC via `ft_transfer_call`, the BTC miner gas fee is determined unilaterally by the relayer when constructing the PSBT — after the user's nBTC has already been committed. The user has no mechanism to specify a per-withdrawal maximum acceptable gas fee. The only bound is the global protocol-wide `max_btc_gas_fee` config value, which can be orders of magnitude higher than the fee at the time the user initiated the withdrawal.

---

### Finding Description

The withdrawal flow proceeds as follows:

1. The user calls `ft_transfer_call` on the `nbtc` contract, specifying `amount` (nBTC to burn) and `withdraw_fee` (bridge fee). At this point the user's nBTC is committed.
2. A relayer constructs a PSBT and submits it to the bridge.
3. The bridge validates the PSBT via `check_withdraw_psbt_valid`.

Inside `check_withdraw_psbt_valid` in `contracts/satoshi-bridge/src/psbt.rs`:

```rust
pub fn check_withdraw_psbt_valid(
    ...
    amount: u128,
    withdraw_fee: u128,
    max_gas_fee: Option<U128>,   // ← optional per-withdrawal cap
) -> (u128, u128) {
``` [1](#0-0) 

The `max_gas_fee` guard is applied only when `Some`:

```rust
if let Some(max_gas_fee) = max_gas_fee {
    require!(
        gas_fee <= max_gas_fee.0,
        ...
    );
}
``` [2](#0-1) 

When `max_gas_fee` is `None`, the only constraint on the gas fee is the global protocol range:

```rust
require!(
    gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
    ...
);
``` [3](#0-2) 

The user's actual received BTC is computed as:

```rust
let max_received_amount = amount - withdraw_fee - gas_fee;
``` [4](#0-3) 

Because the user's withdrawal message (submitted at `ft_transfer_call` time) has no field for a per-withdrawal `max_gas_fee`, the `max_gas_fee` parameter passed into `check_withdraw_psbt_valid` is controlled by the relayer, not the user. The relayer can legitimately pass `None` (no per-withdrawal cap) and set the gas fee anywhere within `[min_btc_gas_fee, max_btc_gas_fee]`. If BTC network fees spike between the user's `ft_transfer_call` and the relayer's PSBT submission, the user receives materially less BTC than they expected, with no recourse — their nBTC is already burned.

The global config bounds `min_btc_gas_fee` / `max_btc_gas_fee` are set by the DAO and can span a wide range: [5](#0-4) 

---

### Impact Explanation

The user burns nBTC (irreversible on NEAR) and receives less BTC than expected because the gas fee — determined after commitment — can be as high as `max_btc_gas_fee`. This constitutes harmful smart-contract behavior: the user suffers a real economic loss (reduced BTC received) without any direct theft by the relayer (excess fee goes to BTC miners). This matches the **Medium** allowed impact: *"Harmful smart-contract behavior without direct funds theft."*

---

### Likelihood Explanation

BTC network fee spikes are common and unpredictable. A relayer acting in good faith will set the fee to whatever the current mempool demands, which can be far above the fee at the time the user initiated the withdrawal. The user has no way to reject this outcome. The entry path is fully unprivileged: any nBTC holder can trigger it by calling `ft_transfer_call`.

---

### Recommendation

Add a `max_gas_fee: Option<U128>` field to the user's withdrawal message (the `TokenReceiverMessage::Withdraw` struct parsed in `ft_on_transfer`). Store this value alongside the pending withdrawal. When the relayer submits the PSBT, pass the stored user-supplied `max_gas_fee` into `check_withdraw_psbt_valid` instead of a relayer-controlled value. This mirrors the existing optional guard already present in `check_withdraw_psbt_valid` — it simply needs to be wired to the user's intent rather than the relayer's discretion.

For consistency, the same pattern should be applied to the refund gas fee: the user already can supply a `gas_fee` in `request_refund`, but there is no upper-bound check to prevent the user from accidentally over-paying. [6](#0-5) 

---

### Proof of Concept

1. Alice calls `ft_transfer_call` on `nbtc`, burning 0.01 BTC worth of nBTC, specifying `withdraw_fee = 1000 sats`. At submission time, BTC fees are 5 sat/vbyte.
2. Before the relayer constructs the PSBT, BTC fees spike to 500 sat/vbyte. The relayer legitimately sets `gas_fee = max_btc_gas_fee` (e.g., 50,000 sats).
3. The relayer calls the bridge with the PSBT, passing `max_gas_fee = None`.
4. `check_withdraw_psbt_valid` passes: `gas_fee` is within `[min_btc_gas_fee, max_btc_gas_fee]`, and no per-user cap is checked.
5. Alice receives `1,000,000 - 1,000 - 50,000 = 949,000 sats` instead of the ~999,000 sats she expected — a ~5% loss she had no ability to prevent or reject. [2](#0-1) [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/psbt.rs (L10-19)
```rust
    pub fn check_withdraw_psbt_valid(
        &self,
        target_btc_address: String,
        withdraw_change_address_script_pubkey: &ScriptBuf,
        withdraw_psbt: &PsbtWrapper,
        vutxos: &[VUTXO],
        amount: u128,
        withdraw_fee: u128,
        max_gas_fee: Option<U128>,
    ) -> (u128, u128) {
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L34-42)
```rust
        if let Some(max_gas_fee) = max_gas_fee {
            require!(
                gas_fee <= max_gas_fee.0,
                format!(
                    "Gas fee does not match the provided max fee (gas fee = {}; max gas fee = {})",
                    gas_fee, max_gas_fee.0
                )
            );
        }
```

**File:** contracts/satoshi-bridge/src/psbt.rs (L238-258)
```rust
        let gas_fee = total_input_amount - total_output_amount;
        // When constructing the withdraw transaction, if the change is less than min_change_amount (dust),
        // the caller may deduct a portion from the user's output to make the change amount meet min_change_amount.
        // Therefore, the contract relaxes the validation.
        let max_received_amount = amount - withdraw_fee - gas_fee;
        let min_received_amount = max_received_amount - config.min_change_amount;
        require!(
            actual_received_amount >= min_received_amount
                && actual_received_amount <= max_received_amount,
            format!(
                "The user's output amount ({}) is out of the valid range ({}, {})",
                actual_received_amount, min_received_amount, max_received_amount
            )
        );
        require!(
            gas_fee >= config.min_btc_gas_fee && gas_fee <= config.max_btc_gas_fee,
            format!(
                "Invalid gas fee ({}). valid range: [{}, {}].",
                gas_fee, config.min_btc_gas_fee, config.max_btc_gas_fee
            )
        );
```

**File:** contracts/satoshi-bridge/src/config.rs (L83-87)
```rust
    #[serde(with = "u128_dec_format")]
    pub min_btc_gas_fee: u128,
    // The max gas fee applicable for Bitcoin transactions
    #[serde(with = "u128_dec_format")]
    pub max_btc_gas_fee: u128,
```

**File:** contracts/satoshi-bridge/src/refund.rs (L549-553)
```rust
        let resolved_gas_fee = gas_fee.unwrap_or_else(|| self.get_refund_gas_fee());
        require!(
            resolved_gas_fee < amount,
            "Gas fee must be less than deposit amount"
        );
```
