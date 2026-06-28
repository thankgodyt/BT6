### Title
Non-Standard ERC20 Token Incompatibility in `fin_transfer` Causes Permanent Freeze of Bridged Funds - (File: `starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract uses `IERC20Dispatcher` for all native-token transfers in `fin_transfer` and `init_transfer`. This dispatcher strictly expects the new Starknet ERC20 standard (SNIP-2) where `transfer` and `transfer_from` return `bool`. Tokens following the old Starknet ERC20 standard (pre-SNIP-2) that do not return a boolean cause the dispatcher to panic. In `fin_transfer`, this makes the finalization permanently uncallable for such tokens, permanently freezing funds that were already burned/locked on the NEAR side.

### Finding Description

`starknet/src/omni_bridge.cairo` imports and uses `IERC20Dispatcher` from OpenZeppelin for Starknet:

```cairo
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
``` [1](#0-0) 

In `fin_transfer`, after the nonce is marked used and the signature is verified, the contract calls:

```cairo
let success = IERC20Dispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
assert(success, 'ERR_TRANSFER_FAILED');
``` [2](#0-1) 

In `init_transfer`, the same pattern is used for the token pull and the native fee:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
``` [3](#0-2) 

```cairo
let success = IERC20Dispatcher { contract_address: native_token }
    .transfer_from(caller, get_contract_address(), native_fee.into());
assert(success, 'ERR_FEE_TRANSFER_FAILED');
``` [4](#0-3) 

`IERC20Dispatcher` is a typed dispatcher that ABI-decodes the return value as `bool`. Old-standard Starknet tokens (pre-SNIP-2) may return `felt252` or return nothing at all from `transfer`/`transfer_from`. When the dispatcher attempts to decode such a return value as `bool`, it panics, reverting the entire transaction.

Notably, the `log_metadata` function already handles both old and new Starknet token standards for `name` and `symbol` via low-level `call_contract_syscall`:

```cairo
let name = if res.len() == 1 {
    // Old standard (felt252)
    ...
} else {
    // New standard (ByteArray)
    ...
};
``` [5](#0-4) 

This demonstrates the bridge is aware of the two-standard ecosystem but does not apply the same defensive handling to token transfers.

The `#[feature("safe_dispatcher")]` attribute is present on the impl block, meaning `IERC20SafeDispatcher` (which returns `Result` instead of panicking) is available but unused. [6](#0-5) 

### Impact Explanation

**Permanent freeze of bridged funds.**

The critical path is:

1. A native Starknet token (old-standard, or one that is later upgraded to non-standard behavior) is locked in the bridge via `init_transfer`. At lock time, `transfer_from` succeeds (e.g., the token was standard at that point, or its `transfer_from` happens to return a decodable value while `transfer` does not).
2. The corresponding NEAR-side finalization mints/releases tokens to the user on NEAR. The NEAR side has now burned or locked its accounting entry — the cross-chain transfer is committed.
3. The user bridges back: NEAR burns/locks the tokens and a relayer submits `fin_transfer` on Starknet.
4. `fin_transfer` calls `IERC20Dispatcher.transfer()`. The token's `transfer` does not return `bool`, causing a panic. The entire transaction reverts.
5. Because Starknet transactions are atomic, `_set_transfer_finalised` is also reverted — the nonce is not consumed. The relayer can retry, but every retry panics identically.
6. The funds are permanently frozen: NEAR has already committed the outbound transfer; Starknet can never release the locked tokens.

The EVM side of the same bridge already uses `SafeERC20` (`safeTransferFrom` / `safeTransfer`) and is not affected. [7](#0-6) 

### Likelihood Explanation

Starknet has a well-documented split between old-standard tokens (pre-SNIP-2, `felt252` returns) and new-standard tokens (SNIP-2, `bool` returns). The bridge's own `log_metadata` already accommodates this split for metadata fields. Any old-standard token registered with the bridge, or any upgradeable token whose implementation changes after locking, triggers this path. The entry point (`fin_transfer`) is public and callable by any relayer with a valid MPC signature, making it reachable by any bridge user whose cross-chain transfer targets Starknet.

### Recommendation

Replace `IERC20Dispatcher` with `IERC20SafeDispatcher` for all token transfer calls in `fin_transfer` and `init_transfer`. `IERC20SafeDispatcher` returns `Result<bool, Array<felt252>>` and does not panic on unexpected return data. Alternatively, use low-level `call_contract_syscall` (as already done in `log_metadata`) and handle both return-value shapes explicitly.

### Proof of Concept

1. Deploy an old-standard Starknet ERC20 token whose `transfer` function returns `felt252` (value `1`) instead of `bool`.
2. Approve the bridge and call `init_transfer` with this token. If `transfer_from` also returns `felt252`, the dispatcher may decode it as `bool` (since `1_felt252` maps to `true` in Cairo's ABI), allowing the lock to succeed.
3. On NEAR, finalize the inbound transfer (NEAR mints tokens to the user).
4. User initiates a return transfer on NEAR; NEAR burns the tokens and emits the event.
5. Relayer calls `fin_transfer` on Starknet with a valid MPC signature.
6. `IERC20Dispatcher { contract_address: token }.transfer(recipient, amount)` panics because the token's `transfer` returns `felt252` but the dispatcher expects `bool` with a specific ABI layout.
7. The transaction reverts. The nonce is not consumed. Every subsequent retry by any relayer produces the same panic.
8. The user's funds are permanently frozen: NEAR has burned them, Starknet can never release the locked balance. [8](#0-7)

### Citations

**File:** starknet/src/omni_bridge.cairo (L40-40)
```text
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
```

**File:** starknet/src/omni_bridge.cairo (L141-143)
```text
    #[abi(embed_v0)]
    #[feature("safe_dispatcher")]
    impl OmniBridgeImpl of super::IOmniBridge<ContractState> {
```

**File:** starknet/src/omni_bridge.cairo (L156-167)
```text
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

**File:** starknet/src/omni_bridge.cairo (L304-306)
```text
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
```

**File:** starknet/src/omni_bridge.cairo (L311-313)
```text
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L395-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
```
