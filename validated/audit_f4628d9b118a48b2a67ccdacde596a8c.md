Audit Report

## Title
Unvalidated BTC/Zcash Destination Address in `init_transfer` Causes Permanent Loss of Bridged Funds - (File: `near/omni-types/src/lib.rs`)

## Summary
`OmniAddress::Btc` and `OmniAddress::Zcash` wrap arbitrary strings with no format validation, while every other chain variant enforces typed parsing. When a user initiates a NEAR→BTC or NEAR→Zcash transfer via `ft_transfer_call` with a malformed address, the bridge immediately and irreversibly burns the user's tokens, stores the unprocessable transfer, and provides no on-chain path for the user to cancel or recover funds.

## Finding Description
`UTXOChainAddress` is a raw `String` type alias with no constraints: [1](#0-0) 

`OmniAddress::from_str` for `"btc"` and `"zcash"` performs zero format validation — it simply wraps the raw string — while every other chain variant calls a typed parser (`H160::parse`, `AccountId::parse`, `SolAddress::parse`, `H256::parse`) that rejects malformed input: [2](#0-1) 

`new_from_slice` similarly accepts any valid UTF-8 byte sequence for BTC/Zcash with no further structural check: [3](#0-2) 

`init_transfer` performs only a chain-kind check (`!= Near`), with no BTC/Zcash address format validation: [4](#0-3) 

`init_transfer_internal` then calls `burn_tokens_if_needed` for NEAR-originated tokens: [5](#0-4) 

The burn is fire-and-forget via `.detach()`, making it irreversible: [6](#0-5) 

`submit_transfer_to_utxo_chain_connector` only checks string equality between the stored recipient and the relayer-supplied address — it does not validate address format either: [7](#0-6) 

`remove_transfer_message` is called inside `submit_transfer_to_utxo_chain_connector` only when the relayer successfully processes the transfer: [8](#0-7) 

A grep across the entire repository confirms there is no `cancel_transfer` or `refund_transfer` function. If the relayer never calls `submit_transfer_to_utxo_chain_connector` (because the address is unprocessable), the entry remains in `pending_transfers` indefinitely with the tokens already burned and no user-callable recovery path.

## Impact Explanation
This is a direct, permanent loss of bridged funds — matching the Critical allowed impact: *"loss … or permanent freezing of bridged funds across … Bitcoin, Zcash."* A user who supplies a syntactically invalid BTC or Zcash address (e.g., `"btc:not-a-real-address"`, an empty string, a wrong-network address, or a garbled bech32 string) will have their wrapped BTC/Zcash tokens permanently burned on NEAR with no corresponding release on the Bitcoin or Zcash chain and no on-chain mechanism to recover the funds.

## Likelihood Explanation
The NEAR bridge is a permissionless, user-facing protocol. BTC and Zcash addresses have non-trivial format requirements (bech32/bech32m encoding, checksum, version bytes, network prefixes). Any user who mistypes an address, pastes a wrong-chain address, or uses a programmatic integration that constructs the address string incorrectly will silently lose funds. No client-side or contract-side guard prevents this. The exploit is triggerable by any unprivileged token holder through a standard `ft_transfer_call`, requires no special privileges, and is repeatable. The codebase itself acknowledges the absence of Zcash address validation in a test comment in `near/omni-tests/src/zcash_stale_transfer_poc.rs`.

## Recommendation
1. Add format validation for `OmniAddress::Btc` and `OmniAddress::Zcash` in both `OmniAddress::from_str` and `new_from_slice`. At minimum, validate bech32/bech32m encoding and network prefix for BTC (mainnet `bc1`/`1`/`3`, testnet `tb1`/`m`/`n`/`2`) and the appropriate Zcash address prefixes (`t1`, `t3`, `zs`, `u`).
2. Add a user-callable `cancel_transfer` function that allows the transfer owner to reclaim their tokens if the transfer has not yet been submitted to the UTXO connector, analogous to the fix applied in the referenced BitVM bridge PR.
3. Consider moving `burn_tokens_if_needed` to occur only after all validation is complete, or making it conditional on a successful downstream acknowledgment rather than fire-and-forget.

## Proof of Concept
1. User holds wrapped BTC (`wbtc.bridge.near`) and calls:
   ```
   ft_transfer_call(
     receiver_id: "omni-bridge.near",
     amount: "1000000",
     msg: '{"InitTransfer": {"recipient": "btc:not-a-real-btc-address", "fee": "0", "native_token_fee": "0"}}'
   )
   ```
2. `ft_on_transfer` → `init_transfer` → `init_transfer_internal` executes. The only check is `recipient.get_chain() != ChainKind::Near`, which passes. `burn_tokens_if_needed` fires and detaches — 1,000,000 units of `wbtc.bridge.near` are permanently burned.
3. The transfer is stored in `pending_transfers` with `recipient = OmniAddress::Btc("not-a-real-btc-address")`.
4. The relayer cannot construct a valid Bitcoin transaction to `"not-a-real-btc-address"` and does not call `submit_transfer_to_utxo_chain_connector`.
5. The user's tokens are permanently gone. There is no on-chain function the user can call to cancel the transfer or recover the burned tokens.

A local integration test can reproduce this by: (a) deploying the bridge and a mock BTC token, (b) calling `ft_transfer_call` with `msg` containing `"btc:INVALID"`, (c) asserting the token balance decreased, and (d) asserting no recovery function exists that restores the balance.

### Citations

**File:** near/omni-types/src/lib.rs (L171-171)
```rust
pub type UTXOChainAddress = String;
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

**File:** near/omni-types/src/lib.rs (L396-411)
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
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
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
