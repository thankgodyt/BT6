Looking at the actual code to validate each claim in the report.

Audit Report

## Title
Same-Token Double-Lock Permanently Freezes STRK and Inflates Cross-Chain Supply When Bridging STRK With Native Fee - (File: `starknet/src/omni_bridge.cairo`)

## Summary
When a user calls `init_transfer` with `token_address == strk_token_address` and `native_fee > 0`, the contract executes two independent `transfer_from` calls on the same STRK ERC-20 contract, locking `amount + native_fee` STRK in the bridge. The `native_fee` portion has no release path on Starknet — no `claim_fee`, rescue, or admin-withdrawal function exists — while the NEAR side mints `native_fee` units of native STRK to the relayer, creating unbacked cross-chain supply and permanently depleting the bridge pool.

## Finding Description

In `init_transfer`, the token pull and the native-fee pull are two independent code paths:

```cairo
// Pull 1: lock the bridged token
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }.burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}

// Pull 2: lock the native fee
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

`is_bridge_token` returns `true` only for tokens deployed via `deploy_token` (those with a `starknet_to_near_token` mapping). STRK is the native Starknet token and is never registered this way, so `is_bridge_token(strk_token_address)` is always `false`. [2](#0-1) 

When `token_address == strk_token_address`, both pulls target the same ERC-20 contract. The bridge receives `amount + native_fee` STRK total, but the `InitTransfer` event records them as separate fields. [3](#0-2) 

The NEAR-side parser reads `amount`, `fee`, and `native_fee` as independent values and constructs an `InitTransferMessage` with both fields populated. [4](#0-3) 

When the NEAR bridge finalizes the transfer, it mints `native_fee` of the native STRK token to the relayer via `.mint()` — creating new on-chain supply — without any corresponding release of STRK from the Starknet bridge. [5](#0-4) 

The only outbound path for locked STRK on Starknet is `fin_transfer`, which releases exactly `payload.amount` to `payload.recipient`. There is no `claim_fee`, rescue, or admin-withdrawal function anywhere in the contract. A grep across all Starknet sources for `claim_fee`, `rescue`, `withdraw`, and `admin_withdraw` returns zero matches. [6](#0-5) 

The `native_fee` STRK locked during `init_transfer` is permanently irrecoverable.

## Impact Explanation

Two concrete, irreversible harms occur simultaneously:

1. **Permanent freezing of bridged funds**: Every user who calls `init_transfer` with `token_address = strk_token_address` and `native_fee > 0` loses `native_fee` STRK permanently. The tokens are locked in the Starknet bridge contract with no release path. This matches the Critical impact class: *permanent freezing of bridged funds*.

2. **Cross-chain supply inflation / escrow mis-accounting**: The NEAR bridge mints `native_fee` units of native STRK to the relayer without any corresponding STRK being releasable from Starknet. The bridge pool holds `native_fee` STRK that can never be disbursed, while the NEAR side has `native_fee` extra native STRK in circulation. If the relayer bridges those tokens back to Starknet, the bridge must consume `native_fee` STRK from other users' deposits to honor the withdrawal, directly depleting the pool. This matches the Critical impact class: *balance manipulation, escrow mis-accounting, fee mis-accounting that changes user or protocol balances*.

Both effects scale linearly with every STRK bridge transfer that includes a non-zero `native_fee`.

## Likelihood Explanation

STRK is the primary native token of Starknet and a natural bridging target. The `native_fee` parameter is a standard, documented part of the bridge interface used to incentivize relayers. Any user bridging STRK to NEAR who sets `native_fee > 0` — the normal relayer-incentive path — triggers this bug. No special privilege, role, or knowledge is required. `init_transfer` is a fully public, permissionless function callable by any account.

## Recommendation

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

Alternatively, when `token_address == strk_token_address`, pull a single combined amount (`amount + native_fee`) in Pull 1 and skip Pull 2, tracking the split internally for event emission only.

## Proof of Concept

1. STRK is deployed on Starknet at address `S`. `is_bridge_token(S)` returns `false` (STRK is not a `deploy_token`-registered bridge token).
2. User calls:
   ```
   init_transfer(
     token_address = S,    // STRK
     amount        = 1000,
     fee           = 10,
     native_fee    = 50,   // also STRK
     recipient     = "alice.near",
     message       = ""
   )
   ```
3. Starknet contract executes:
   - Pull 1: `transfer_from(user, bridge, 1000)` — 1000 STRK locked
   - Pull 2: `transfer_from(user, bridge, 50)` — 50 STRK locked
   - Total STRK locked in bridge: **1050**
4. `InitTransfer` event emitted with `amount=1000, fee=10, native_fee=50`.
5. NEAR relayer parses the event; NEAR bridge mints 990 wrapped STRK to Alice and mints 50 native STRK to the relayer.
6. The 50 STRK locked as `native_fee` has no release path. `fin_transfer` on Starknet only releases `payload.amount` to a recipient — it cannot recover the `native_fee` STRK.
7. Result: 50 STRK permanently frozen in the Starknet bridge; 50 extra native STRK minted on NEAR with no releasable backing. If the relayer bridges their 50 native STRK back to Starknet, the bridge must consume 50 STRK from other users' deposits, directly stealing from the pool.

A local integration test can confirm this by: (a) deploying the Starknet bridge with a mock STRK token, (b) calling `init_transfer` with `token_address = strk_token_address` and `native_fee > 0`, (c) asserting the bridge holds `amount + native_fee` STRK, (d) attempting every outbound function (`fin_transfer` with any valid payload) and confirming no path releases the `native_fee` portion.

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

**File:** starknet/src/omni_bridge.cairo (L378-380)
```text
        fn is_bridge_token(self: @ContractState, token_address: ContractAddress) -> bool {
            self.starknet_to_near_token.read(token_address).len() > 0
        }
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
