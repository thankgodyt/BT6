The code is clear. Let me trace the exact logic before rendering a verdict.

### Title
Trusted Relayer Can Bypass `max_gas_fee` Constraint on BTC Withdrawals When User `msg` Lacks `MaxGasFee` Variant — (`near/omni-bridge/src/btc.rs`)

---

### Summary

The `max_gas_fee` validation in `submit_transfer_to_utxo_chain_connector` is conditional: it only fires when the user's stored `msg` deserializes as `DestinationChainMsg::MaxGasFee`. When the user's `msg` is empty, unparseable, or is the `DestHexMsg` variant, the check is skipped entirely, and the relayer's caller-supplied `max_gas_fee` is forwarded unchecked to the BTC connector via `ft_transfer_call`. A malicious trusted relayer can exploit this to inflate the gas fee deducted from the user's BTC output.

---

### Finding Description

In `submit_transfer_to_utxo_chain_connector`, the bridge reads the user's on-chain `msg` and attempts to extract a `max_gas_fee` constraint:

```rust
let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
    .and_then(|s| s.max_gas_fee());

if let Some(max_gas_fee_msg) = max_gas_fee_msg {
    require!(
        max_gas_fee.expect("max_gas_fee is missing") == max_gas_fee_msg,
        "Invalid max gas fee"
    );
}
``` [1](#0-0) 

`DestinationChainMsg::from_json` returns `None` on any parse failure (empty string, invalid JSON, unknown variant). [2](#0-1) 

`DestinationChainMsg::max_gas_fee()` also returns `None` when the variant is `DestHexMsg` rather than `MaxGasFee`. [3](#0-2) 

In both cases `max_gas_fee_msg` is `None`, the `if let Some(...)` block is skipped, and the relayer's `max_gas_fee` value inside the `TokenReceiverMessage::Withdraw` is never validated against anything the user committed to on-chain.

The raw relayer-supplied `msg` string — including the unchecked `max_gas_fee` — is then forwarded verbatim to the BTC connector:

```rust
.ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
``` [4](#0-3) 

The BTC connector uses this `max_gas_fee` field from `TokenReceiverMessage::Withdraw` to determine the maximum gas fee it may deduct from the user's satoshi output. [5](#0-4) 

---

### Impact Explanation

A malicious trusted relayer targeting a pending BTC transfer whose `msg` is empty (or is a `DestHexMsg`) can set `max_gas_fee` to the connector's configured ceiling (e.g., `max_btc_gas_fee: 80000` satoshis per the deployment config) regardless of actual network fee conditions. The connector will deduct up to that inflated ceiling from the user's output, reducing the satoshis delivered to the user's BTC address. This is a direct, relayer-controlled fee mis-accounting that changes user balances — the user receives fewer satoshis than they are owed.

---

### Likelihood Explanation

The attacker must hold the trusted relayer role, which requires staking and an application/waiting period. This is a privileged but non-admin role reachable through the normal production relayer onboarding path. Any transfer initiated without an explicit `MaxGasFee` in the `msg` — including all transfers from EVM chains to BTC where the source chain message format uses `DestHexMsg` or no `msg` at all — is vulnerable. This covers a large fraction of real production transfers.

---

### Recommendation

Remove the conditional and always enforce the constraint. When the user's stored `msg` contains no `MaxGasFee`, the bridge should either:

1. Require `max_gas_fee` in the relayer's `TokenReceiverMessage::Withdraw` to be `None` (no gas fee deduction allowed beyond the connector's own cap), or
2. Reject the call if `max_gas_fee` is `Some(...)` and the user's `msg` does not contain a matching `MaxGasFee` commitment.

The simplest safe fix:

```rust
let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
    .and_then(|s| s.max_gas_fee());

// Always enforce: relayer's max_gas_fee must match what the user committed to,
// or be None if the user did not specify one.
require!(
    max_gas_fee == max_gas_fee_msg,
    "Invalid max gas fee"
);
```

---

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC token contract with `msg` = `""` (empty) or `{"DestHexMsg":""}`, initiating a BTC withdrawal. The transfer is stored in `pending_transfers` with `transfer.message.msg = ""`.

2. Trusted relayer calls `submit_transfer_to_utxo_chain_connector` with:
   ```json
   {
     "transfer_id": { "origin_chain": "Near", "origin_nonce": 1 },
     "msg": "{\"Withdraw\":{\"target_btc_address\":\"<user_btc_addr>\",\"input\":[],\"output\":[],\"max_gas_fee\":\"80000\"}}",
     "fee_recipient": null,
     "fee": null
   }
   ```

3. At line 54–55, `DestinationChainMsg::from_json("")` returns `None`, so `max_gas_fee_msg = None`.

4. The `if let Some(...)` block at line 57 is skipped — no validation occurs.

5. The bridge calls `ft_transfer_call` on the nBTC token, forwarding the relayer's `msg` (with `max_gas_fee = 80000`) to the BTC connector.

6. The BTC connector deducts up to 80,000 satoshis as gas fee from the user's output, even if the actual network fee is 1,000 satoshis. The user receives 79,000 fewer satoshis than they are owed.

7. The bridge contract never rejected the call, confirming the invariant is broken.

### Citations

**File:** near/omni-bridge/src/btc.rs (L54-62)
```rust
                let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
                    .and_then(|s| s.max_gas_fee());

                if let Some(max_gas_fee_msg) = max_gas_fee_msg {
                    require!(
                        max_gas_fee.expect("max_gas_fee is missing") == max_gas_fee_msg,
                        "Invalid max gas fee"
                    );
                }
```

**File:** near/omni-bridge/src/btc.rs (L91-91)
```rust
            .ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
```

**File:** near/omni-types/src/lib.rs (L922-929)
```rust
impl DestinationChainMsg {
    pub fn max_gas_fee(&self) -> Option<U128> {
        if let Self::MaxGasFee(fee) = self {
            Some(U128(fee.0.into()))
        } else {
            None
        }
    }
```

**File:** near/omni-types/src/lib.rs (L939-941)
```rust
    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
```

**File:** near/omni-types/src/btc.rs (L10-15)
```rust
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
    },
```
