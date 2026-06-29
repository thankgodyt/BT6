### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` Without Actual-Received-Amount Verification — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `initTransfer` function locks ERC-20 tokens by calling `safeTransferFrom(msg.sender, address(this), amount)` and then unconditionally emits `InitTransfer` with the caller-supplied `amount`. For fee-on-transfer tokens, the bridge receives strictly less than `amount`, but the emitted event still claims the full `amount` was locked. The NEAR bridge processes this event and mints the full `amount` on NEAR, creating an undercollateralized EVM escrow. An attacker can exploit this to extract more tokens from the EVM escrow than were ever deposited.

---

### Finding Description

In `initTransfer`, the else-branch for ordinary ERC-20 tokens is:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
``` [1](#0-0) 

Immediately after, the event is emitted with the caller-supplied `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,   // ← always the caller-supplied value, never the actual received amount
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

There is no balance-before / balance-after check anywhere in `initTransfer`. `SafeERC20.safeTransferFrom` only verifies that the call did not revert and returned `true`; it does not verify the net amount credited to the bridge.

`initTransfer` has no token whitelist — any ERC-20 address is accepted: [3](#0-2) 

Token registration on the EVM side is permissionless via `logMetadata`:

```solidity
function logMetadata(address tokenAddress) external payable {
    ...
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [4](#0-3) 

The `ICustomMinter` interface used in the parallel `customMinters` path also has no post-call balance verification: [5](#0-4) 

---

### Impact Explanation

The EVM escrow becomes undercollateralized relative to the total supply minted on NEAR. An attacker who bridges a fee-on-transfer token receives a full `amount` of NEAR-side tokens while the bridge only holds `amount × (1 − fee_rate)` EVM tokens. When the attacker (or any user) bridges back, the bridge pays out from the shared escrow pool. If the pool has been topped up by honest users, the attacker extracts more EVM tokens than they deposited — a direct theft from other users' locked funds. This is a **critical escrow mis-accounting / balance manipulation** impact.

---

### Likelihood Explanation

- `initTransfer` accepts any ERC-20 token with no whitelist check.
- `logMetadata` is fully permissionless; any caller can emit a `LogMetadata` event for any token address.
- Fee-on-transfer tokens are a well-known, deployed token class (e.g., reflection tokens, tokens with built-in tax).
- The only prerequisite is that the NEAR bridge's relayer processes the `LogMetadata` event and registers the token on NEAR — consistent with the hub-and-spoke relayer model described in the architecture.
- No admin keys, private key leaks, or validator collusion are required.

---

### Recommendation

Record the bridge's actual balance change rather than trusting the caller-supplied `amount`. Apply the same pattern recommended in the referenced report:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 balanceAfter = IERC20(tokenAddress).balanceOf(address(this));
uint128 actualReceived = uint128(balanceAfter - balanceBefore);
require(actualReceived == amount, "fee-on-transfer token not supported");
```

Use `actualReceived` (not `amount`) in the `InitTransfer` event and all downstream accounting. Alternatively, maintain an explicit token whitelist so only pre-vetted tokens can be bridged.

---

### Proof of Concept

1. Attacker deploys `MaliciousToken` — a standard ERC-20 that deducts a 50 % transfer fee on every `transferFrom`, crediting the fee to the attacker's wallet.
2. Attacker calls `OmniBridge.logMetadata(MaliciousToken)` (no access control). The `LogMetadata` event is emitted; the NEAR relayer picks it up and registers the token on NEAR.
3. Attacker calls `OmniBridge.initTransfer(MaliciousToken, 1000, 0, 0, "attacker.near", "")`.
   - `safeTransferFrom` moves 1000 tokens from attacker → bridge, but the fee hook retains 500; bridge receives **500**.
   - `InitTransfer` is emitted with `amount = 1000`.
4. NEAR bridge verifies the EVM proof and mints **1000** `MaliciousToken` wrapped tokens to `attacker.near`.
5. Attacker sells or bridges back the 1000 NEAR-side tokens. On bridge-back, `finTransfer` calls `IERC20(MaliciousToken).safeTransfer(attacker, 1000)`. The bridge only holds 500 of its own, so it drains 500 tokens belonging to honest depositors.
6. Net result: attacker extracted 500 EVM tokens from other users' locked funds. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L331-355)
```text
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
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
```

**File:** evm/src/common/ICustomMinter.sol (L1-7)
```text
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.24;

interface ICustomMinter {
    function mint(address token, address to, uint128 amount) external;
    function burn(address token, uint128 amount) external;
}
```
