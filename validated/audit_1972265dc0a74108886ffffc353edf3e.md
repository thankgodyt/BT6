### Title
Unchecked Multiplication in `denormalize_amount()` Causes Permanent Loss of Bridged Funds in `fin_transfer_callback` - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`denormalize_amount()` performs an unchecked `u128` multiplication. When a user initiates a transfer on the EVM chain with an amount large enough that `amount × 10^diff_decimals` overflows `u128`, the NEAR bridge's `fin_transfer_callback` panics. Because `overflow-checks = true` is set in the workspace, the panic reverts all state changes — but the user's tokens were already irreversibly burned or locked on the EVM side with no refund path, resulting in permanent loss of bridged funds.

### Finding Description

`denormalize_amount` at line 2776 performs a bare multiplication with no overflow guard:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))   // ← unchecked; panics on overflow
}
``` [1](#0-0) 

This function is called inside `fin_transfer_callback` with `init_transfer.amount.0`, a value read directly from the verified EVM `InitTransfer` event proof:

```rust
let transfer_message = TransferMessage {
    amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
    fee: Self::denormalize_fee(&init_transfer.fee, decimals),
    ...
};
``` [2](#0-1) 

The EVM `initTransfer` function accepts any `uint128 amount` and only validates `fee < amount` — it imposes no upper bound that would prevent the denormalized result from exceeding `u128::MAX`:

```solidity
function initTransfer(address tokenAddress, uint128 amount, uint128 fee, ...)
    external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    if (fee >= amount) { revert InvalidFee(); }
    ...
    emit BridgeTypes.InitTransfer(..., amount, fee, ...);
}
``` [3](#0-2) 

The `FinTransfer` event on the EVM side (used by `claim_fee`) is not affected because its amount is derived from a NEAR-signed payload that was already normalized, so `denormalize(normalize(x)) ≤ x` holds there. The vulnerable path is exclusively the **EVM → NEAR** direction through `fin_transfer_callback`.

The CLAUDE.md false-positive note #2 ("Decimal Arithmetic Underflow") covers only the case where `origin_decimals < decimals` (causing `origin_decimals - decimals` to underflow). The overflow described here occurs in the **expected** configuration where `origin_decimals > decimals` and the user supplies a large amount — a completely different code path. [4](#0-3) 

### Impact Explanation

When the panic fires inside `fin_transfer_callback`:

1. NEAR's transaction atomicity reverts all state mutations in the callback.
2

### Citations

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
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
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
