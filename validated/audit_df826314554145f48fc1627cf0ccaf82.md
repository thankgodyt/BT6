### Title
Old-Standard Starknet ERC20 Tokens With No Boolean Return From `transfer` Cause Permanent Freezing of Bridged Funds in `fin_transfer` — (`starknet/src/omni_bridge.cairo`)

---

### Summary

`fin_transfer` and `init_transfer` in the Starknet bridge contract use `IERC20Dispatcher` (OpenZeppelin new-standard) which expects a `bool` return value from `transfer` and `transfer_from`. Old-standard Starknet tokens (pre-OpenZeppelin v0.7) return nothing (`()`) from these functions. When such a token is the destination asset in a cross-chain transfer, every `fin_transfer` attempt panics during ABI deserialization, permanently freezing the user's funds: they are already locked or burned on NEAR but can never be released on Starknet.

---

### Finding Description

Starknet has two historical ERC20 standards:

- **Old standard** (pre-OZ v0.7): `transfer` and `transfer_from` return `()` (unit/nothing). `name` and `symbol` return `felt252`.
- **New standard** (OZ v0.7+): `transfer` and `transfer_from` return `bool`. `name` and `symbol` return `ByteArray`.

The `log_metadata` function already acknowledges this split explicitly in a developer comment and uses raw `call_contract_syscall` with length-based branching to handle both: [1](#0-0) 

However, `fin_transfer` and `init_transfer` use `IERC20Dispatcher` — the new-standard dispatcher — which unconditionally deserializes a `bool` from the return data: [2](#0-1) [3](#0-2) 

When `IERC20Dispatcher.transfer()` is called on an old-standard token that returns nothing, Cairo's ABI deserialization finds an empty return span and panics. The entire transaction reverts.

The import confirms the new-standard dispatcher is used with no fallback: [4](#0-3) 

---

### Impact Explanation

**`fin_transfer` — Critical: permanent freezing of bridged funds.**

A user initiates a transfer of an old-standard token from NEAR (or any other chain) to Starknet. On the NEAR side, the tokens are locked or burned. The relayer then calls `fin_transfer` on Starknet. The call always reverts because `IERC20Dispatcher.transfer()` panics on the empty return. Since the entire transaction reverts, the nonce bitmap update at line 250 is also rolled back: [5](#0-4) 

Every subsequent retry by any relayer fails identically. The user's funds are permanently frozen: locked/burned on NEAR with no on-chain recovery path on Starknet.

**`init_transfer` — Medium: denial of service, no fund loss.**

A user calling `init_transfer` with an old-standard token gets a revert before any state is committed. No funds are lost, but the token is permanently unusable for outbound transfers from Starknet. [6](#0-5) 

---

### Likelihood Explanation

Old-standard tokens are prevalent on Starknet mainnet. The ETH token (`0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7`) is referenced directly in the test suite as a known old-standard token: [7](#0-6) 

The `log_metadata` function's explicit dual-standard handling with a developer comment proves the team is aware these tokens exist and are expected to be bridged. Any user who calls `log_metadata` for an old-standard token (which succeeds) and then initiates a cross-chain transfer will have their funds permanently frozen when `fin_transfer` is attempted.

---

### Recommendation

Mirror the dual-standard approach already used in `log_metadata`. Use raw `call_contract_syscall` for `transfer` and `transfer_from`, inspect the return span length, and treat an empty return (old standard, no revert) as success:

```cairo
// In fin_transfer, replace IERC20Dispatcher.transfer() with:
let call_data: Array<felt252> = array![];
let mut transfer_args: Array<felt252> = array![];
payload.recipient.serialize(ref transfer_args);
let amount_u256: u256 = payload.amount.into();
amount_u256.serialize(ref transfer_args);

let ret = syscalls::call_contract_syscall(
    payload.token_address, selector!("transfer"), transfer_args.span(),
).unwrap_syscall();

// Old standard returns nothing; new standard returns bool
if ret.len() > 0 {
    let success = OptionTrait::expect(
        Serde::<bool>::deserialize(ref ret.clone()), 'ERR_TRANSFER_FAILED'
    );
    assert(success, 'ERR_TRANSFER_FAILED');
}
// Empty return = old standard, transfer did not revert = success
```

Apply the same pattern to `transfer_from` in `init_transfer`.

---

### Proof of Concept

1. Deploy an old-standard ERC20 token on Starknet (one whose `transfer` returns `()`).
2. Call `log_metadata` on the bridge for this token — it succeeds because `log_metadata` uses raw syscalls.
3. Initiate a transfer of this token from NEAR to Starknet (locking/burning funds on NEAR).
4. Relayer calls `fin_transfer` on the Starknet bridge with a valid MPC signature.
5. `IERC20Dispatcher { contract_address: payload.token_address }.transfer(...)` panics: the return span is empty but `bool` deserialization requires one `felt252` element.
6. Transaction reverts. Nonce is not persisted. Every retry fails identically.
7. User's funds are permanently frozen: burned on NEAR, unreachable on Starknet. [8](#0-7)

### Citations

**File:** starknet/src/omni_bridge.cairo (L40-40)
```text
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
```

**File:** starknet/src/omni_bridge.cairo (L144-167)
```text
        fn log_metadata(ref self: ContractState, token: ContractAddress) {
            // There are two possible metadata standards in use.
            // 1. Old style: name and symbol are felt252 values.
            // 2. New style: name and symbol are ByteArray values (ERC20 ABI).
            // We are using low-level contract calls to determine the type.

            let call_data: Array<felt252> = array![];
            let mut res = syscalls::call_contract_syscall(
                token, selector!("name"), call_data.span(),
            )
                .unwrap_syscall();

            let name = if res.len() == 1 {
                // Old standard (felt252)
                let name = OptionTrait::expect(
                    Serde::<felt252>::deserialize(ref res), 'Could not deserialize name',
                );
                utils::felt252_to_string(name)
            } else {
                // New standard (ByteArray)
                OptionTrait::expect(
                    Serde::<ByteArray>::deserialize(ref res), 'Could not deserialize name',
                )
            };
```

**File:** starknet/src/omni_bridge.cairo (L242-263)
```text
        fn fin_transfer(
            ref self: ContractState, signature: Signature, payload: TransferMessagePayload,
        ) {
            assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');

            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L303-307)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```

**File:** starknet/tests/test_contract.cairo (L171-174)
```text
    let eth_token_address = 0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7
        .try_into()
        .unwrap();
    dispatcher.log_metadata(eth_token_address);
```
