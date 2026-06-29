Now I have all the information needed. Let me analyze the exact validation logic in `submit_transfer_to_utxo_chain_connector`.

The code is unambiguous. Here is the complete analysis:

---

### Title
Unvalidated `output` Array in `submit_transfer_to_utxo_chain_connector` Allows Trusted Relayer to Redirect MPC-Signed Bitcoin Transaction to Attacker Address — (`near/omni-bridge/src/btc.rs`)

### Summary
`submit_transfer_to_utxo_chain_connector` validates only `target_btc_address` against the stored recipient, but explicitly ignores the `output: Vec<TxOut>` field (bound to `_`). The raw relayer-supplied `msg` string — including the unvalidated `output` array — is forwarded verbatim to the UTXO connector. A malicious trusted relayer can set `target_btc_address = VICTIM_ADDR` (passing the check) while embedding `script_pubkey = ATTACKER_SCRIPT` in the `output` array, causing the connector to request an MPC signature over a Bitcoin transaction that pays the attacker.

### Finding Description

In `near/omni-bridge/src/btc.rs`, the destructuring pattern at lines 42–52 explicitly discards both `input` and `output`:

```rust
if let TokenReceiverMessage::Withdraw {
    target_btc_address,
    input: _,    // ← never inspected
    output: _,   // ← never inspected
    max_gas_fee,
} = message
{
    require!(
        btc_address == target_btc_address,
        BridgeError::IncorrectTargetUtxoAddress.as_ref()
    );
``` [1](#0-0) 

After this check passes, the function forwards the **original, unmodified `msg` string** to the connector:

```rust
.ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
``` [2](#0-1) 

The `msg` string is the raw JSON supplied by the relayer, which contains the attacker-controlled `output` array. The `TxOut` struct carries a free-form `script_pubkey: String` field with no constraints: [3](#0-2) 

The connector receives this `msg` via `ft_on_transfer` and uses the `output` array to construct the Bitcoin transaction it submits to MPC for signing. There is no downstream re-validation of `script_pubkey` against the stored recipient in the bridge contract.

### Impact Explanation

A malicious trusted relayer can steal 100% of any pending NEAR-to-BTC transfer. The MPC threshold-signature scheme signs whatever transaction the connector presents; the bridge is the only place where the recipient address could be enforced, and it fails to do so for the `output` array. The signed Bitcoin transaction pays `ATTACKER_SCRIPT`, not the victim's address.

### Likelihood Explanation

Any account holding the `TrustedRelayer` role can execute this attack. Trusted relayers are operational participants (not DAO-level admins); the role is granted to bridge operators and potentially third-party relayer services. A single compromised or malicious trusted relayer is sufficient. The attack requires no brute force, no key leakage, and no collusion beyond the single relayer role.

### Recommendation

After deserializing `message`, extract and validate the `output` array before forwarding `msg`. Specifically:

1. Derive the expected `script_pubkey` from `btc_address` (the stored recipient) using the appropriate Bitcoin address-to-script encoding.
2. Assert that every `TxOut` in `output` whose `value > 0` has a `script_pubkey` matching the expected recipient script (allowing a single change output back to the bridge's MPC key if needed).
3. Alternatively, do not accept a relayer-supplied `output` array at all — reconstruct the `output` inside the bridge from the stored `recipient` and `amount`, then pass that reconstructed message to the connector.

### Proof of Concept

Call sequence on unmodified code:

1. User calls `ft_transfer_call` → bridge's `ft_on_transfer` → `init_transfer` with `recipient = btc:VICTIM_ADDR`. A `TransferMessage` is stored in `pending_transfers` with `recipient = OmniAddress::Btc("VICTIM_ADDR")`.

2. Malicious trusted relayer calls:
```json
submit_transfer_to_utxo_chain_connector(
  transfer_id: { origin_chain: "Near", origin_nonce: 1 },
  msg: "{\"Withdraw\":{\"target_btc_address\":\"VICTIM_ADDR\",\"input\":[],\"output\":[{\"value\":100000,\"script_pubkey\":\"ATTACKER_SCRIPT\"}],\"max_gas_fee\":null}}",
  fee_recipient: null,
  fee: null
)
```

3. Bridge check at line 50: `"VICTIM_ADDR" == "VICTIM_ADDR"` → passes. `output` is bound to `_` and never inspected.

4. Bridge calls `ft_transfer_call(connector, amount, None, msg)` where `msg` is the attacker's raw JSON string containing `ATTACKER_SCRIPT`.

5. Connector's `ft_on_transfer` receives the message, parses `output`, constructs a Bitcoin PSBT paying `ATTACKER_SCRIPT`, and calls MPC sign.

6. MPC signs the transaction. Funds are delivered to the attacker. [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/btc.rs (L41-91)
```rust
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

        if let Some(fee) = &fee {
            require!(
                &transfer.message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let chain_kind = transfer.message.get_destination_chain();
        let btc_account_id = self.get_utxo_chain_token(chain_kind);
        require!(
            self.get_token_id(&transfer.message.token) == btc_account_id,
            BridgeError::NativeTokenRequiredForChain.as_ref()
        );

        self.remove_transfer_message(transfer_id);

        let fee_recipient = fee_recipient.unwrap_or(env::predecessor_account_id());

        ext_token::ext(btc_account_id)
            .with_attached_deposit(ONE_YOCTO)
            .with_static_gas(FT_TRANSFER_CALL_GAS)
            .ft_transfer_call(self.get_utxo_chain_connector(chain_kind), amount, None, msg)
```

**File:** near/omni-types/src/btc.rs (L7-16)
```rust
#[derive(Debug, Serialize, Deserialize)]
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

**File:** near/omni-types/src/btc.rs (L25-30)
```rust
#[near(serializers=[json])]
#[derive(Debug)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: String,
}
```
