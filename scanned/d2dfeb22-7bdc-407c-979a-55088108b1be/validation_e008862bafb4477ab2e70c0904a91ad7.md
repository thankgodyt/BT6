### Title
Missing Validation That UTXO Output Values Match Transfer Amount in `submit_transfer_to_utxo_chain_connector` - (File: `near/omni-bridge/src/btc.rs`)

### Summary
`submit_transfer_to_utxo_chain_connector` in `near/omni-bridge/src/btc.rs` validates the recipient address and optional max gas fee from the relayer-supplied `TokenReceiverMessage::Withdraw`, but explicitly ignores the `input` and `output` fields. No check enforces that the sum of `output` values plus the gas fee equals the transfer `amount`. A malicious trusted relayer can craft outputs where only a fraction of the user's nBTC is delivered as BTC on-chain, with the remainder silently consumed as miner fees.

### Finding Description

In `submit_transfer_to_utxo_chain_connector`, the relayer supplies a `msg` string that deserializes into a `TokenReceiverMessage::Withdraw`:

```rust
TokenReceiverMessage::Withdraw {
    target_btc_address,
    input: _,   // ignored
    output: _,  // ignored
    max_gas_fee,
}
``` [1](#0-0) 

The contract validates only that `target_btc_address` matches the stored recipient and that `max_gas_fee` matches the stored value (when present). The `input` and `output` fields are bound to `_` and never inspected. [2](#0-1) 

The computed `amount` — the correct number of nBTC satoshis to deliver — is:

```rust
let amount = U128(transfer.message.amount.0 - transfer.message.fee.fee.0);
``` [3](#0-2) 

This `amount` of nBTC tokens is transferred to the connector, and the raw `msg` (containing the unchecked `output` list) is forwarded verbatim:

```rust
.ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
``` [4](#0-3) 

There is no assertion that `sum(output[i].value) + gas_fee == amount`. The connector receives the correct nBTC token amount but constructs the Bitcoin transaction from the relayer-supplied `output` list, which may allocate far less than `amount` satoshis to the recipient, with the remainder going to miners.

The `TokenReceiverMessage` type confirms `output` is a free-form `Vec<TxOut>` with no on-chain constraints: [5](#0-4) 

### Impact Explanation

A malicious trusted relayer calls `submit_transfer_to_utxo_chain_connector` with a crafted `output` list where the output to the recipient is 1 satoshi and the remaining `amount - 1 - gas_fee` satoshis are implicitly donated to miners (by simply omitting a change output). The user's nBTC is burned on NEAR (the transfer is removed from `pending_transfers` at line 84 before the cross-contract call), but the user receives only 1 satoshi of BTC. This constitutes permanent loss of bridged funds. [6](#0-5) 

### Likelihood Explanation

Any account can become a trusted relayer by calling `apply_for_trusted_relayer` and staking the required NEAR. After the waiting period elapses, the account is promoted automatically. The objective explicitly lists "custom relayer" as a valid attacker type. The staking requirement is a deterrent, not a cryptographic guarantee, and the profit from stealing large BTC withdrawals can far exceed the stake. [7](#0-6) 

### Recommendation

Before forwarding `msg` to the connector, validate that the sum of all `output` values plus the gas fee does not exceed `amount`, and that at least one output delivers exactly `amount - gas_fee` satoshis to `target_btc_address`. Concretely, re-parse the `output` field inside the match arm (instead of binding it to `_`) and assert:

```
sum(output[i].value) + actual_gas_fee == amount
output[recipient_index].value == amount - actual_gas_fee
```

This mirrors the fix recommended in the Lombard report: sum UTXO inputs and outputs to ensure the unspent difference does not silently become miner fees.

### Proof of Concept

1. User initiates a NEAR → BTC transfer of 1,000,000 satoshis (1 nBTC), paying a 1,000-satoshi bridge fee. The bridge stores `amount = 999,000` in `pending_transfers`.
2. Malicious trusted relayer calls `submit_transfer_to_utxo_chain_connector` with:
   ```json
   {
     "Withdraw": {
       "target_btc_address": "<user's BTC address>",
       "input": ["<valid UTXO outpoint>"],
       "output": [{"value": 1, "script_pubkey": "<user's scriptPubKey>"}],
       "max_gas_fee": null
     }
   }
   ```
3. The bridge validates `target_btc_address` ✓ and `max_gas_fee` (absent) ✓. It does not check that `output[0].value (1) + gas_fee == 999,000`.
4. The bridge removes the transfer from `pending_transfers` and calls `ft_transfer_call` sending 999,000 nBTC to the connector with the crafted `msg`.
5. The connector constructs a Bitcoin transaction with a single 1-satoshi output; the remaining 998,999 satoshis become miner fees.
6. The user receives 1 satoshi on Bitcoin. Their 999,000 nBTC is permanently burned. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/btc.rs (L23-29)
```rust
#[trusted_relayer]
#[near]
impl Contract {
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn submit_transfer_to_utxo_chain_connector(
```

**File:** near/omni-bridge/src/btc.rs (L38-68)
```rust
        let message = serde_json::from_str::<TokenReceiverMessage>(&msg).expect("INVALID MSG");
        let amount = U128(transfer.message.amount.0 - transfer.message.fee.fee.0);

        if let Some(btc_address) = transfer.message.recipient.get_utxo_address() {
            if let TokenReceiverMessage::Withdraw {
                target_btc_address,
                input: _,
                output: _,
                max_gas_fee,
            } = message
            {
                require!(
                    btc_address == target_btc_address,
                    BridgeError::IncorrectTargetUtxoAddress.as_ref()
                );

                let max_gas_fee_msg = DestinationChainMsg::from_json(&transfer.message.msg)
                    .and_then(|s| s.max_gas_fee());

                if let Some(max_gas_fee_msg) = max_gas_fee_msg {
                    require!(
                        max_gas_fee.expect("max_gas_fee is missing") == max_gas_fee_msg,
                        "Invalid max gas fee"
                    );
                }
            } else {
                env::panic_str("Invalid message type");
            }
        } else {
            env::panic_str("Invalid destination chain");
        }
```

**File:** near/omni-bridge/src/btc.rs (L84-84)
```rust
        self.remove_transfer_message(transfer_id);
```

**File:** near/omni-bridge/src/btc.rs (L88-91)
```rust
        ext_token::ext(btc_account_id)
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(FT_TRANSFER_CALL_GAS)
            .ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
```

**File:** near/omni-types/src/btc.rs (L8-16)
```rust
pub enum TokenReceiverMessage {
    DepositProtocolFee,
    Withdraw {
        target_btc_address: String,
        input: Vec<OutPoint>,
        output: Vec<TxOut>,
        max_gas_fee: Option<U128>,
    },
}
```
