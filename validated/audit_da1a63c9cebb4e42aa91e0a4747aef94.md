### Title
Case-Sensitive BTC/Zcash Address Comparison Causes Permanent Transfer Freeze - (File: near/omni-bridge/src/btc.rs)

### Summary

The `submit_transfer_to_utxo_chain_connector` function performs a raw, case-sensitive string equality check between the recipient address stored in the transfer message and the `target_btc_address` supplied by the relayer. Because `OmniAddress::Btc` and `OmniAddress::Zcash` store addresses as unvalidated, unnormalized `String` values, any case difference between the two sides causes the check to fail and the transfer to be permanently unfinalizeable, freezing the user's bridged funds.

### Finding Description

`OmniAddress::Btc(UTXOChainAddress)` and `OmniAddress::Zcash(UTXOChainAddress)` are defined as raw `String` wrappers with no format validation or case normalization applied at parse time. [1](#0-0) 

When `OmniAddress::from_str` parses a `btc:` or `zcash:` address, it stores the recipient string verbatim: [2](#0-1) 

Similarly, `new_from_slice` for BTC/Zcash performs only a UTF-8 validity check, not case normalization: [3](#0-2) 

In `submit_transfer_to_utxo_chain_connector`, the stored recipient address is compared directly against the relayer-supplied `target_btc_address` using Rust's `==` operator, which is a byte-exact, case-sensitive comparison: [4](#0-3) 

Bitcoin Bech32 addresses (BIP-173) are defined as case-insensitive; the spec mandates all-lowercase output from encoders, but decoders must accept both cases. Zcash Sapling/Orchard addresses (Bech32m) follow the same rule. A user who submits a transfer with a mixed-case or uppercase Bech32 recipient (e.g., `BC1QRPNZ62A9QPQZ2NMDEAH8FJDPYARNVAVULHLE26`) will have that exact string stored. A relayer implementation that normalizes addresses to canonical lowercase before constructing the `TokenReceiverMessage::Withdraw` JSON will supply `bc1qrpnz62a9qpqz2nmdeah8fjdpyarnvavulhle26`, causing the `require!` to panic and the transfer to remain in storage indefinitely.

There is no user-facing cancellation path for UTXO transfers. The `submit_transfer_to_btc_connector_callback` only re-inserts the transfer when the downstream connector call fails; it does not handle the case where the upstream address check panics. Once the relayer's normalization behavior is fixed in code, the stored transfer with the non-canonical address can never be matched. [5](#0-4) 

### Impact Explanation

A user whose BTC or Zcash transfer is stored with a non-canonical-case address cannot have that transfer finalized by any relayer that follows the BIP-173 canonical lowercase convention. The user's tokens are permanently locked in the bridge with no recovery path. This constitutes permanent freezing of bridged funds on the Bitcoin and Zcash flows.

### Likelihood Explanation

Bech32 and Bech32m addresses are explicitly case-insensitive by specification. Wallets and block explorers routinely display them in uppercase or mixed case. Any relayer that calls `.to_lowercase()` on the recipient address before constructing the withdrawal message — a natural defensive coding practice — will trigger this failure for any transfer whose stored address is not already all-lowercase. The user-controlled entry point (`ft_transfer_call` with an `InitTransferMsg` containing an uppercase Bech32 recipient) is fully reachable by any token holder.

### Recommendation

Normalize BTC and Zcash addresses to lowercase at the point of storage (in `OmniAddress::from_str` and `new_from_slice`) and/or at the point of comparison in `submit_transfer_to_utxo_chain_connector`. For example:

```rust
// In from_str:
"btc" => Ok(Self::Btc(recipient.to_lowercase())),
"zcash" => Ok(Self::Zcash(recipient.to_lowercase())),

// Or in submit_transfer_to_utxo_chain_connector:
require!(
    btc_address.to_lowercase() == target_btc_address.to_lowercase(),
    BridgeError::IncorrectTargetUtxoAddress.as_ref()
);
```

Normalizing at parse time is preferable because it also ensures consistent storage keys and prevents duplicate transfers that differ only in case.

### Proof of Concept

1. User calls `ft_transfer_call` on the nBTC token with `msg = InitTransferMsg { recipient: "btc:BC1QRPNZ62A9QPQZ2NMDEAH8FJDPYARNVAVULHLE26", ... }`.
2. Bridge stores `OmniAddress::Btc("BC1QRPNZ62A9QPQZ2NMDEAH8FJDPYARNVAVULHLE26")` in the transfer message.
3. Trusted relayer reads the transfer, normalizes the Bech32 address to canonical lowercase `bc1qrpnz62a9qpqz2nmdeah8fjdpyarnvavulhle26`, and calls `submit_transfer_to_utxo_chain_connector` with `target_btc_address = "bc1qrpnz62a9qpqz2nmdeah8fjdpyarnvavulhle26"`.
4. The `require!(btc_address == target_btc_address, ...)` check fails because `"BC1Q..."` ≠ `"bc1q..."`.
5. The function panics; the transfer message remains in storage.
6. No relayer following BIP-173 canonical encoding can ever finalize this transfer.
7. The user has no cancel function to recover their locked nBTC. [4](#0-3) [2](#0-1)

### Citations

**File:** near/omni-types/src/lib.rs (L170-193)
```rust
pub type EvmAddress = H160;
pub type UTXOChainAddress = String;
pub type StarknetAddress = H256;

pub const ZERO_ACCOUNT_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[near(serializers=[borsh])]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum OmniAddress {
    Eth(EvmAddress),
    Near(AccountId),
    Sol(SolAddress),
    Arb(EvmAddress),
    Base(EvmAddress),
    Bnb(EvmAddress),
    Btc(UTXOChainAddress),
    Zcash(UTXOChainAddress),
    Pol(EvmAddress),
    HyperEvm(EvmAddress),
    Strk(StarknetAddress),
    Abs(EvmAddress),
    Fogo(SolAddress),
}
```

**File:** near/omni-types/src/lib.rs (L245-252)
```rust
            ChainKind::Btc => Ok(Self::Btc(
                String::from_utf8(address.to_vec())
                    .map_err(|e| format!("Invalid BTC address: {e}"))?,
            )),
            ChainKind::Zcash => Ok(Self::Zcash(
                String::from_utf8(address.to_vec())
                    .map_err(|e| format!("Invalid ZCash address: {e}"))?,
            )),
```

**File:** near/omni-types/src/lib.rs (L405-406)
```rust
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
```

**File:** near/omni-bridge/src/btc.rs (L41-52)
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
```

**File:** near/omni-bridge/src/btc.rs (L103-126)
```rust
    #[private]
    pub fn submit_transfer_to_btc_connector_callback(
        &mut self,
        transfer_msg: TransferMessage,
        transfer_owner: AccountId,
        fee_recipient: AccountId,
        #[callback_result] call_result: &Result<U128, PromiseError>,
    ) -> PromiseOrValue<()> {
        if matches!(call_result, Ok(result) if result.0 > 0) {
            let token_fee = transfer_msg.fee.fee.0;
            self.send_fee_internal(&transfer_msg, fee_recipient, token_fee)
        } else {
            let required_storage_balance =
                self.add_transfer_message(transfer_msg, transfer_owner.clone());

            self.update_storage_balance(
                transfer_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            );

            PromiseOrValue::Value(())
        }
    }
```
