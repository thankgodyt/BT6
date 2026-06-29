### Title
`HlBridgeToken.mint(address,uint256,bytes)` Delivers Zero Tokens to Bridge Recipient When `message` Is Non-Empty — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

---

### Summary

`HlBridgeToken` overrides the 3-argument `mint(address account, uint256 value, bytes memory)` to first mint tokens to `account` and then immediately transfer all of them to `_systemAddress`. When `OmniBridge.finTransfer` is called with a non-empty `message` field for an `HlBridgeToken`, it dispatches the 3-arg `mint`, causing the bridge recipient to receive **zero tokens** while the bridge marks the nonce as used and emits a `FinTransfer` event — permanently losing the user's funds.

---

### Finding Description

`OmniBridge.finTransfer` selects between the 2-arg and 3-arg `mint` overloads based on whether `payload.message` is empty: [1](#0-0) 

```solidity
} else if (isBridgeToken[payload.tokenAddress]) {
    if (payload.message.length == 0) {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
    } else {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount, payload.message);
    }
}
```

For a standard `BridgeToken` the 3-arg overload simply ignores the bytes parameter and mints normally. `HlBridgeToken` overrides it differently: [2](#0-1) 

```solidity
function mint(address account, uint256 value, bytes memory) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);
}
```

`_mint(account, value)` increases `account`'s balance by `value`. `_update(account, _systemAddress, value)` immediately transfers the entire `value` from `account` to `_systemAddress`. The net effect on `account` (the bridge recipient) is **zero**. All minted tokens land at `_systemAddress`.

The bridge then emits `FinTransfer` and marks `completedTransfers[payload.destinationNonce] = true`: [3](#0-2) 

The nonce is consumed and the transfer is irrevocably finalised, but the recipient holds nothing.

---

### Impact Explanation

Any user who bridges tokens from NEAR to HyperEVM and includes a non-empty `message` (e.g., to trigger `ft_transfer_call`-style behaviour on the destination) will have their funds permanently redirected to `_systemAddress`. The bridge considers the transfer complete; there is no retry or refund path. This is a direct, permanent loss of bridged funds for every affected user.

---

### Likelihood Explanation

The `message` field is freely set by the originating user during `initTransfer` or `ft_on_transfer` on NEAR. Any user who passes a non-empty message — a common pattern for cross-chain contract calls — triggers the bug. No special privilege or coordination is required. The only prerequisite is that `HlBridgeToken` is registered in `OmniBridge` with `isBridgeToken[addr] = true` and no custom minter, which is the natural registration path for a token that is itself the mint authority.

---

### Recommendation

The 3-arg `mint` in `HlBridgeToken` must not silently redirect tokens away from `account`. Two options:

1. **Override to behave identically to the 2-arg path** (ignore the bytes parameter and simply call `_mint(account, value)`), reserving the HyperCore parking behaviour exclusively for the `coreReceiveWithData` path.
2. **Revert in the 3-arg overload** if called from a context other than `coreReceiveWithData`, preventing `finTransfer` from ever invoking the HyperCore-specific accounting path.

Additionally, `finTransfer` should not silently change token-delivery semantics based on the `message` field; the 3-arg dispatch should be removed or guarded so that recipient delivery is always unconditional.

---

### Proof of Concept

1. User on NEAR calls `ft_on_transfer` with `msg = '{"InitTransfer":{"recipient":"evm:0xRecipient","fee":"0","native_token_fee":"0","msg":"hello"}}'` — a non-empty `msg` is forwarded as `payload.message`.
2. NEAR MPC signs the `TransferMessagePayload` including the non-empty `message`.
3. Relayer calls `OmniBridge.finTransfer(signature, payload)` on HyperEVM.
4. Because `payload.message.length != 0` and `isBridgeToken[payload.tokenAddress] == true`, the branch at line 344 executes: `IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount, payload.message)`.
5. `HlBridgeToken.mint` runs: `_mint(recipient, amount)` then `_update(recipient, _systemAddress, amount)`.
6. `recipient.balanceOf == 0`; `_systemAddress.balanceOf += amount`.
7. `completedTransfers[nonce] = true`; `FinTransfer` event emitted — transfer is finalised with no recourse. [2](#0-1) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L76-83)
```text
    function mint(
        address account,
        uint256 value,
        bytes memory
    ) external override onlyOwner {
        _mint(account, value);
        _update(account, _systemAddress, value);
    }
```
