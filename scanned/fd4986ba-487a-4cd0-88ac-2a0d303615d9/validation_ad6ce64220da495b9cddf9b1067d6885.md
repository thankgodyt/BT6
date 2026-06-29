### Title
Same-Token Double-Lock Causes Permanent STRK Loss and Supply Inflation When Bridging STRK With Native Fee - (File: `starknet/src/omni_bridge.cairo`)

### Summary
In the Starknet bridge contract's `init_transfer`, when a user bridges STRK (the native fee token) and also pays a non-zero `native_fee` in STRK, the contract performs two separate `transfer_from` calls on the same token contract. The `native_fee` portion of STRK is permanently locked in the Starknet contract with no release mechanism, while the NEAR side mints a corresponding wrapped STRK token to the relayer — inflating cross-chain supply.

### Finding Description

`init_transfer` in `starknet/src/omni_bridge.cairo` handles the bridged token and the native fee token as two independent ERC-20 pulls:

```cairo
// Pull 1: bridge the token
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    // ...
}

// Pull 2: pull native fee in STRK
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    // ...
}
``` [1](#0-0) 

When `token_address == strk_token_address` and STRK is not a bridge token (it is a native/locked asset), both pulls execute on the same ERC-20 contract. The contract receives `amount + native_fee` of STRK total.

The `InitTransfer` event records `token_address`, `amount`, and `native_fee` separately: [2](#0-1) 

The NEAR-side event parser (`parse_init_transfer`) reads these as independent fields and constructs an `InitTransferMessage` with `token = STRK` and `fee.native_fee = native_fee`: [3](#0-2) 

When the NEAR bridge finalizes this inbound transfer, it mints `amount - fee` of wrapped STRK to the recipient and then mints `native_fee` of the native STRK token (via `get_native_token_id(ChainKind::Strk)`) to the relayer: [4](#0-3) 

The Starknet contract has **no `claim_fee` function, no rescue function, and no mechanism to release the `native_fee` STRK**. The only outbound path for locked STRK is `fin_transfer`, which only releases `payload.amount` to `payload.recipient`: [5](#0-4) 

The `native_fee` STRK is permanently irrecoverable.

### Impact Explanation

Two simultaneous harms occur:

1. **Permanent fund loss**: Every user who calls `init_transfer` with `token_address = strk_token_address` and `native_fee > 0` loses `native_fee` STRK permanently. The tokens are locked in the Starknet contract with no release path.

2. **Cross-chain supply inflation**: The NEAR bridge mints `native_fee` units of the native STRK token to the relayer on NEAR without any corresponding STRK being released from Starknet. This inflates the total cross-chain STRK supply, breaking the 1:1 backing invariant that the bridge relies on.

Both effects are irreversible and scale with every STRK bridge transfer that includes a native fee.

### Likelihood Explanation

STRK is the primary native token of Starknet and a high-value bridging target. The `native_fee` parameter is a standard, documented part of the bridge interface used to incentivize relayers. Any user bridging STRK to another chain who sets `native_fee > 0` (the normal relayer-incentive path) triggers this bug. No special knowledge or privilege is required — `init_transfer` is a fully public, permissionless function.

### Recommendation

Add a guard in `init_transfer` that prevents `token_address` from equaling `strk_token_address` when `native_fee > 0`:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    assert(token_address != native_token, 'ERR_TOKEN_IS_NATIVE_FEE_TOKEN');
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
```

Alternatively, when `token_address == strk_token_address`, pull a single combined amount (`amount + native_fee`) and track the split internally, or require `native_fee == 0` for STRK transfers.

### Proof of Concept

1. STRK is deployed on Starknet at address `S`. It is not a bridge token (`is_bridge_token(S) == false`).
2. Attacker/user calls:
   ```
   init_transfer(
     token_address = S,   // STRK
     amount       = 1000,
     fee          = 10,
     native_fee   = 50,   // also STRK
     recipient    = "alice.near",
     message      = ""
   )
   ```
3. Starknet contract executes:
   - Pull 1: `transfer_from(user, bridge, 1000)` — 1000 STRK locked
   - Pull 2: `transfer_from(user, bridge, 50)` — 50 STRK locked
   - Total STRK locked in bridge: **1050**
4. `InitTransfer` event emitted with `amount=1000, native_fee=50`.
5. NEAR relayer picks up the event. NEAR bridge mints 990 wrapped STRK to Alice and mints 50 native STRK to the relayer.
6. The 50 STRK locked in the Starknet contract as `native_fee` has no release path. `fin_transfer` on Starknet only releases `payload.amount` to a recipient — it cannot be used to recover the `native_fee` STRK.
7. Result: 50 STRK permanently frozen in the Starknet bridge contract; 50 extra wrapped STRK minted on NEAR with no backing.

### Citations

**File:** starknet/src/omni_bridge.cairo (L256-263)
```text
            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L300-314)
```text
            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L316-330)
```text
            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```

**File:** near/omni-types/src/starknet/events.rs (L54-75)
```rust
    let amount = cursor.read_u128()?;
    let fee = cursor.read_u128()?;
    let native_fee = cursor.read_u128()?;
    let recipient_str = cursor.read_byte_array()?;
    let msg = cursor.read_byte_array()?;

    let emitter_address = OmniAddress::Strk(H256(*from_address));
    let recipient: OmniAddress = recipient_str.parse().map_err(stringify)?;

    Ok(InitTransferMessage {
        origin_nonce,
        token,
        amount: near_sdk::json_types::U128(amount),
        recipient,
        fee: Fee {
            fee: near_sdk::json_types::U128(fee),
            native_fee: near_sdk::json_types::U128(native_fee),
        },
        sender,
        msg,
        emitter_address,
    })
```

**File:** near/omni-bridge/src/lib.rs (L1736-1743)
```rust
            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```
