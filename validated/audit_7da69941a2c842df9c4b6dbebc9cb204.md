Audit Report

## Title
`IERC20Dispatcher` Bool-Return Assumption Causes Permanent Freezing of Bridged Funds for Old Cairo 0 ERC20 Tokens — (`File: starknet/src/omni_bridge.cairo`)

## Summary

The Starknet bridge contract uses `IERC20Dispatcher` for `transfer` and `transfer_from` calls, which unconditionally deserializes the return data as `bool`. Old Cairo 0 ERC20 tokens on Starknet mainnet (e.g., early USDC, USDT) return nothing from these functions, causing the dispatcher to panic and revert the transaction. In `fin_transfer`, this makes it impossible to release funds to any recipient holding such a token, effectively freezing bridged assets until an admin upgrade is performed.

## Finding Description

In `fin_transfer`, for any token where `is_bridge_token` returns `false`, the contract executes:

```cairo
let success = IERC20Dispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
assert(success, 'ERR_TRANSFER_FAILED');
``` [1](#0-0) 

`IERC20Dispatcher` is the standard (non-safe) OpenZeppelin Cairo dispatcher. It calls the target contract and unconditionally attempts to deserialize the return span as `bool`. If the token returns an empty span (no return value), deserialization panics and the entire transaction reverts.

Old Cairo 0 ERC20 tokens — deployed before the OpenZeppelin Cairo v0.7.0 ABI standard — have `transfer` and `transfer_from` entrypoints that emit no return value. These tokens are live on Starknet mainnet and are legitimate bridging candidates.

The same pattern appears in `init_transfer` for both the bridged token and the native fee token: [2](#0-1) 

Notably, the `log_metadata` function already handles old vs. new ABI standards by using low-level `call_contract_syscall` and inspecting return length: [3](#0-2) 

This demonstrates developer awareness of the old/new standard incompatibility, but the same care was not applied to the ERC20 transfer calls.

The impl block carries `#[feature("safe_dispatcher")]` at line 142, which enables use of `IERC20SafeDispatcher` but does not change the behavior of `IERC20Dispatcher` — the non-safe variant is still used explicitly throughout. [4](#0-3) 

Because Starknet transactions are atomic, the panic reverts all state changes including the nonce write at line 250: [5](#0-4) 

The nonce is never consumed, so every subsequent retry of `fin_transfer` for the same payload hits the same panic. The funds locked on the source chain (NEAR or EVM) cannot be released on Starknet until an admin upgrades the contract.

## Impact Explanation

**Critical — permanent freezing of bridged funds.** Any cross-chain transfer targeting a native Starknet token deployed under the old Cairo 0 ERC20 ABI will be unreleasable on the Starknet side. The source-chain funds are locked, the destination nonce is never consumed (due to revert), and every retry produces the same panic. This matches the allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet."* The contract is upgradeable, so an admin can eventually fix it, but until then all affected transfers are frozen with no user recourse.

## Likelihood Explanation

**Medium.** No special attacker capability is required. Any ordinary user who initiates a cross-chain transfer of an old Cairo 0 ERC20 token (e.g., early USDC or USDT on Starknet mainnet) to a Starknet address triggers this path. The affected tokens are high-value, widely held, and still live on Starknet mainnet. A relayer calling `fin_transfer` with a valid MPC signature for such a payload is sufficient to trigger the freeze.

## Recommendation

Replace `IERC20Dispatcher` with `IERC20SafeDispatcher` (OpenZeppelin Cairo's safe variant) at all three call sites. The safe dispatcher wraps the call in a `Result`, allowing graceful handling of empty or unexpected return data without panicking:

```cairo
// fin_transfer
let result = IERC20SafeDispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
match result {
    Result::Ok(success) => assert(success, 'ERR_TRANSFER_FAILED'),
    Result::Err(_) => panic_with_felt252('ERR_TRANSFER_FAILED'),
}

// init_transfer (token)
let result = IERC20SafeDispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
match result {
    Result::Ok(success) => assert(success, 'ERR_TRANSFER_FROM_FAILED'),
    Result::Err(_) => panic_with_felt252('ERR_TRANSFER_FROM_FAILED'),
}

// init_transfer (native fee)
let result = IERC20SafeDispatcher { contract_address: native_token }
    .transfer_from(caller, get_contract_address(), native_fee.into());
match result {
    Result::Ok(success) => assert(success, 'ERR_FEE_TRANSFER_FAILED'),
    Result::Err(_) => panic_with_felt252('ERR_FEE_TRANSFER_FAILED'),
}
```

Alternatively, for old Cairo 0 tokens that return nothing but succeed, the `Result::Err` branch could be treated as success (matching the behavior of Ethereum's `SafeERC20`), depending on the desired semantics.

## Proof of Concept

1. Deploy a mock Cairo contract implementing the old Cairo 0 ERC20 ABI: `transfer` and `transfer_from` entrypoints that execute successfully but return nothing (empty return span).
2. Deploy the `OmniBridge` contract on a local Starknet testnet (snforge). Pre-fund the bridge contract with the mock token.
3. Construct a valid `TransferMessagePayload` targeting the mock token address with `is_bridge_token` returning `false`.
4. Sign the payload with the test MPC key (as done in `test_fin_transfer_with_bridge_token`).
5. Call `fin_transfer` with the signed payload.
6. Observe: the transaction panics during `IERC20Dispatcher.transfer` deserialization. The nonce is not consumed. The bridge's token balance is unchanged.
7. Retry `fin_transfer` with the same payload — same panic occurs every time.
8. Confirm that the equivalent funds on the source chain remain locked with no release path until a contract upgrade.

### Citations

**File:** starknet/src/omni_bridge.cairo (L141-143)
```text
    #[abi(embed_v0)]
    #[feature("safe_dispatcher")]
    impl OmniBridgeImpl of super::IOmniBridge<ContractState> {
```

**File:** starknet/src/omni_bridge.cairo (L151-167)
```text
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

**File:** starknet/src/omni_bridge.cairo (L247-250)
```text
            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);
```

**File:** starknet/src/omni_bridge.cairo (L260-262)
```text
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
```

**File:** starknet/src/omni_bridge.cairo (L303-313)
```text
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
```
