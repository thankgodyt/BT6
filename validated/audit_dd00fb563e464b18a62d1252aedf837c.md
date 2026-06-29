### Title
Unvalidated BTC/Zcash Destination Address in `init_transfer` Causes Permanent Loss of Bridged Funds - (File: `near/omni-types/src/lib.rs`)

### Summary
`OmniAddress::Btc` and `OmniAddress::Zcash` accept any arbitrary string without format validation. When a user initiates a NEAR→BTC or NEAR→Zcash peg-out via `ft_transfer_call`, their tokens are burned immediately. If the supplied BTC/Zcash address is syntactically invalid, the relayer cannot construct a valid on-chain transaction, the transfer is permanently stuck, and there is no user-callable cancel or refund path.

### Finding Description
`UTXOChainAddress` is defined as a raw `String` type alias with no constraints: [1](#0-0) 

The `OmniAddress::FromStr` implementation for `btc` and `zcash` chains performs zero format validation — it simply wraps the raw string: [2](#0-1) 

Compare this to every other chain variant, which parses through a typed validator (`H160::parse`, `AccountId::parse`, `SolAddress::parse`, `H256::parse`) that rejects malformed input: [3](#0-2) 

The `init_transfer` function in the bridge contract performs only a chain-kind check (not NEAR), with no BTC/Zcash address format check: [4](#0-3) 

Immediately after, `init_transfer_internal` burns the user's tokens via `burn_tokens_if_needed` before any further validation: [5](#0-4) 

The burn is fire-and-forget (`.detach()`), so it is irreversible: [6](#0-5) 

The `submit_transfer_to_utxo_chain_connector` function (the relayer-side peg-out step) only checks that the relayer-supplied `target_btc_address` matches the stored recipient string — it does not validate the address format either: [7](#0-6) 

There is no user-callable cancel or refund function for a pending transfer. Once `remove_transfer_message` is called inside `submit_transfer_to_utxo_chain_connector`, the entry is gone; if the relayer never calls it (because the address is unprocessable), the entry stays in `pending_transfers` indefinitely with the tokens already burned. [8](#0-7) 

### Impact Explanation
A user who supplies a syntactically invalid BTC or Zcash address (e.g., `"btc:not-a-real-address"`, an empty string, a Zcash address on the BTC chain, or a garbled bech32 string) will have their wrapped BTC/Zcash tokens permanently burned on NEAR with no corresponding release on the Bitcoin or Zcash chain and no on-chain mechanism to recover the funds. This is a direct, permanent loss of bridged funds.

### Likelihood Explanation
The NEAR bridge is a permissionless, user-facing protocol. BTC and Zcash addresses have non-trivial format requirements (bech32/bech32m encoding, checksum, version bytes, network prefixes). A user who mistypes an address, pastes a wrong-chain address, or uses a programmatic integration that constructs the address string incorrectly will silently lose funds. No client-side or contract-side guard prevents this. The codebase itself acknowledges the absence of Zcash address validation in a test comment: [9](#0-8) 

### Recommendation
Add format validation for `OmniAddress::Btc` and `OmniAddress::Zcash` in `OmniAddress::from_str` (and in `new_from_slice`). At minimum, validate bech32/bech32m encoding and network prefix for BTC (mainnet `bc1`/`1`/`3`, testnet `tb1`/`m`/`n`/`2`) and the appropriate Zcash address prefixes (`t1`, `t3`, `zs`, `u`). Additionally, add a user-callable `cancel_transfer` function that allows the transfer owner to reclaim their tokens if the transfer has not yet been submitted to the UTXO connector, analogous to the fix applied in the referenced BitVM bridge PR.

### Proof of Concept
1. User holds wrapped BTC (`wbtc.bridge.near`) and calls:
   ```
   ft_transfer_call(
     receiver_id: "omni-bridge.near",
     amount: "1000000",
     msg: '{"InitTransfer": {"recipient": "btc:not-a-real-btc-address", "fee": "0", "native_token_fee": "0"}}'
   )
   ```
2. `ft_on_transfer` → `init_transfer` → `init_transfer_internal` executes. The only check is `recipient.get_chain() != ChainKind::Near`, which passes. `burn_tokens_if_needed` fires and detaches — 1,000,000 units of `wbtc.bridge.near` are burned.
3. The transfer is stored in `pending_transfers` with `recipient = OmniAddress::Btc("not-a-real-btc-address")`.
4. The relayer cannot construct a valid Bitcoin transaction to `"not-a-real-btc-address"` and does not call `submit_transfer_to_utxo_chain_connector`.
5. The user's tokens are permanently gone. There is no on-chain function the user can call to cancel the transfer or recover the burned tokens. [2](#0-1) [4](#0-3) [6](#0-5)

### Citations

**File:** near/omni-types/src/lib.rs (L171-171)
```rust
pub type UTXOChainAddress = String;
```

**File:** near/omni-types/src/lib.rs (L396-408)
```rust
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
```

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1806-1812)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1851)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
```

**File:** near/omni-bridge/src/btc.rs (L49-52)
```rust
                require!(
                    btc_address == target_btc_address,
                    BridgeError::IncorrectTargetUtxoAddress.as_ref()
                );
```

**File:** near/omni-bridge/src/btc.rs (L84-84)
```rust
        self.remove_transfer_message(transfer_id);
```

**File:** near/omni-tests/src/zcash_stale_transfer_poc.rs (L196-197)
```rust
        // A 500-char "Zcash UA" string. The bridge doesn't validate Zcash
        // address format — `OmniAddress::Zcash(String)` accepts anything —
```
