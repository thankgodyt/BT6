### Title
Unbounded `msg` String and `Withdraw` Variant Vectors in `ft_on_transfer` Allow Gas Exhaustion DoS - (File: `contracts/satoshi-bridge/src/api/token_receiver.rs`)

---

### Summary
The `ft_on_transfer` function accepts a `msg: String` parameter with no size limit. The `Withdraw` variant of `TokenReceiverMessage` further contains `input: Vec<OutPoint>` and `output: Vec<TxOut>` with no element-count bounds. Any nBTC token holder can craft a withdrawal message with an arbitrarily large `input` or `output` array (bounded only by NEAR's 4 MB transaction limit), causing gas exhaustion in the bridge's withdrawal processing path.

---

### Finding Description

`ft_on_transfer` in `token_receiver.rs` is the bridge's NEP-141 receiver, invoked by any nBTC holder via `ft_transfer_call`. It immediately deserializes the raw `msg: String` with `serde_json::from_str` and then dispatches the `Withdraw` variant's `input: Vec<OutPoint>` and `output: Vec<TxOut>` directly to `ft_on_transfer_withdraw_chain_specific` — with no size check on any of these fields. [1](#0-0) 

The `msg` string is parsed without any length guard: [2](#0-1) 

The `Withdraw` variant's `input` and `output` vectors are passed directly downstream: [3](#0-2) 

By contrast, the `request_refund` path does enforce a hard cap (`MAX_REQUEST_REFUND_TX_BYTES = 200_000`) on `tx_bytes`: [4](#0-3) [5](#0-4) 

No equivalent guard exists for `ft_on_transfer`'s `msg`, `input`, or `output`.

---

### Impact Explanation

An attacker with any nBTC balance can call `ft_transfer_call` with a `msg` containing thousands of `OutPoint` entries in `input` or `TxOut` entries in `output` (NEAR's 4 MB transaction cap allows ~50,000 `OutPoint` entries in JSON). Processing this in `ft_on_transfer_withdraw_chain_specific` — which iterates over `input` to look up UTXOs and builds a PSBT — will exhaust the 300 Tgas per-transaction gas budget. The withdrawal call panics, and the nBTC tokens are returned to the sender by the NEP-141 `ft_transfer_call` rollback. No direct fund theft occurs, but the attacker can repeatedly trigger this to degrade the withdrawal path.

**Impact: Low** — publicly reachable panic-driven fault in the production bridge withdrawal path without direct theft.

---

### Likelihood Explanation

Any nBTC token holder can trigger this with a single `ft_

### Citations

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L7-18)
```rust
#[near(serializers = [json])]
pub enum TokenReceiverMessage {
    DepositProtocolFee,
    // Here is the withdraw message structure that will be sent from user or dApp to the btc/zcash connector
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
        chain_specific_data: Option<ChainSpecificData>,
    },
}
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L34-34)
```rust
        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
```

**File:** contracts/satoshi-bridge/src/api/token_receiver.rs (L51-65)
```rust
            TokenReceiverMessage::Withdraw {
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            } => self.ft_on_transfer_withdraw_chain_specific(
                sender_id,
                amount,
                target_btc_address,
                input,
                output,
                max_gas_fee,
                chain_specific_data,
            ),
```

**File:** contracts/satoshi-bridge/src/refund.rs (L26-26)
```rust
pub(crate) const MAX_REQUEST_REFUND_TX_BYTES: usize = 200_000;
```

**File:** contracts/satoshi-bridge/src/refund.rs (L150-153)
```rust
        require!(
            tx_bytes.0.len() <= MAX_REQUEST_REFUND_TX_BYTES,
            "tx_bytes too large for refund request"
        );
```
