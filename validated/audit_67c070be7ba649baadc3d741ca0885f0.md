### Title
`IERC20Dispatcher` Bool-Return Assumption Permanently Freezes Bridged Funds for Non-Standard Starknet Tokens — (`File: starknet/src/omni_bridge.cairo`)

---

### Summary

The Starknet bridge contract calls `IERC20Dispatcher { ... }.transfer(...)` and `.transfer_from(...)` and asserts the returned `bool`. Starknet tokens deployed under the old Cairo 0 ERC20 standard (pre-OpenZeppelin Cairo v0.7.0) do not return any value from these functions. When the dispatcher attempts to deserialize the empty return data as `bool`, the call panics and the transaction reverts. In `fin_transfer`, this makes it impossible to ever release funds to a recipient, permanently freezing bridged assets.

---

### Finding Description

`OmniBridge.sol` (EVM) correctly applies `SafeERC20` throughout: [1](#0-0) [2](#0-1) 

The Starknet contract does not have an equivalent safe-dispatch wrapper. In `fin_transfer`, for any token that is not a bridge-deployed token, the contract calls: [3](#0-2) 

In `init_transfer`, the same pattern is used for both the bridged token and the native fee token: [4](#0-3) 

`IERC20Dispatcher` is the non-safe OpenZeppelin Cairo dispatcher. It calls the target contract and unconditionally deserializes the return data as `bool`. If the token returns nothing (empty return span), deserialization panics and the entire transaction reverts.

Old Cairo 0 ERC20 tokens on Starknet mainnet (e.g., early USDC, USDT, and other tokens deployed before the new ABI standard) have `transfer` and `transfer_from` that return nothing. These tokens are still live on Starknet mainnet and are legitimate bridging candidates.

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

In `fin_transfer`, the destination nonce is marked used *before* the transfer call: [5](#0-4) 

Because the nonce write and the transfer are in the same transaction, a panic on the transfer reverts the nonce write too. The nonce is never consumed. Every subsequent retry of `fin_transfer` for that payload will also panic at the same point. The funds locked on the source chain (NEAR or EVM) can never be released on Starknet — they are permanently frozen.

---

### Likelihood Explanation

**Medium.** Starknet mainnet hosts multiple high-value tokens (early USDC, USDT, and others) deployed under the old Cairo 0 ERC20 ABI that return nothing from `transfer`/`transfer_from`. Any user who initiates a cross-chain transfer of such a token to Starknet triggers this path. No special attacker capability is required — a normal bridge user holding one of these tokens is sufficient.

---

### Recommendation

Replace `IERC20Dispatcher` with `IERC20SafeDispatcher` (OpenZeppelin Cairo's safe variant), which wraps the call in a `Result` and allows graceful error handling without panicking on unexpected return data. This is the Cairo analog of Ethereum's `SafeERC20`.

```cairo
// Instead of:
let success = IERC20Dispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
assert(success, 'ERR_TRANSFER_FAILED');

// Use:
let result = IERC20SafeDispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
match result {
    Result::Ok(success) => assert(success, 'ERR_TRANSFER_FAILED'),
    Result::Err(_) => panic_with_felt252('ERR_TRANSFER_FAILED'),
}
```

Apply the same fix to both `transfer_from` call sites in `init_transfer`.

---

### Proof of Concept

1. A Starknet-native token `T` was deployed under the old Cairo 0 ERC20 standard. Its `transfer` function has no return value.
2. A user on NEAR calls the NEAR bridge to send `100 T` to a Starknet address. The NEAR side locks the funds and emits a cross-chain message.
3. A relayer calls `fin_transfer` on the Starknet `OmniBridge` with the signed payload.
4. `_set_transfer_finalised` marks the nonce (line 250), then `_verify_borsh_signature` passes (line 252–254).
5. `is_bridge_token(T)` returns `false` (T is a native Starknet token, not a bridge-deployed token).
6. `IERC20Dispatcher { contract_address: T }.transfer(recipient, 100)` is called. Token `T` returns nothing.
7. The dispatcher attempts to deserialize the empty return span as `bool` — this panics.
8. The entire transaction reverts. The nonce is not consumed.
9. Every retry of step 3 produces the same panic. The 100 T equivalent locked on NEAR can never be released on Starknet. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L34-34)
```text
    using SafeERC20 for IERC20;
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

**File:** starknet/src/omni_bridge.cairo (L247-263)
```text
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
