### Title
Silent Success on Destroyed Bridge Token Enables Unauthorized Cross-Chain Minting and Permanent Fund Loss — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol` makes high-level Solidity calls to `IBridgeToken.mint()` and `BridgeToken.burn()` — both `void`-returning functions — without first verifying that the target address contains deployed code. When a bridge token contract is destroyed, the EVM returns `success = true` with empty return data for any CALL to a zero-code address. Because `mint` and `burn` return nothing, Solidity's ABI decoder does not fail, and the call silently succeeds. This produces two distinct critical impacts depending on which code path is hit.

---

### Finding Description

In `finTransfer`, after marking the nonce consumed, the contract calls:

```solidity
IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
```

In `initTransfer`, the contract calls:

```solidity
BridgeToken(tokenAddress).burn(msg.sender, amount);
```

Neither call is preceded by an `EXTCODESIZE` check or any equivalent contract-existence guard. `SafeERC20` (used in the non-bridge-token path at line 351 and line 395) does perform such a check, but the `isBridgeToken` branch bypasses `SafeERC20` entirely and calls the token directly.

The `isBridgeToken` mapping lives in the bridge contract's own storage and is never automatically cleared when a token contract is destroyed. Once a token is registered, `isBridgeToken[addr] == true` persists indefinitely. [1](#0-0) [2](#0-1) [3](#0-2) 

---

### Impact Explanation

**Path 1 — `initTransfer` (unauthorized minting on NEAR):**
An attacker calls `initTransfer(destroyedBridgeToken, amount, ...)`. The `isBridgeToken` guard passes. `BridgeToken(destroyedToken).burn(msg.sender, amount)` silently succeeds — no tokens are burned. The `InitTransfer` event is emitted with the full `amount`. A relayer submits this event to NEAR, which mints the corresponding tokens to the attacker's recipient. The attacker receives bridged tokens on NEAR without locking or burning anything on EVM. This is unauthorized cross-chain minting.

**Path 2 — `finTransfer` (permanent fund loss):**
A relayer calls `finTransfer` for a legitimate inbound transfer. `completedTransfers[payload.destinationNonce] = true` is set first, consuming the nonce. Then `IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount)` silently succeeds on the destroyed contract — no tokens are minted. The nonce is permanently consumed, the user's NEAR-side funds are already locked/burned, and the recipient receives nothing. Funds are permanently lost with no recourse. [4](#0-3) [5](#0-4) 

---

### Likelihood Explanation

Post-EIP-6780 (Cancun), `selfdestruct` no longer clears code unless called in the same transaction as deployment, reducing the likelihood on fully upgraded chains. However:

1. The bridge targets multiple EVM chains (Ethereum, Arbitrum, Base, BNB, Polygon, HyperEVM, Abstract), and not all have identical EIP-6780 semantics or upgrade timelines.
2. The `BridgeToken` is a UUPS upgradeable proxy. If the shared implementation contract is selfdestructed (a known UUPS attack vector), all proxies delegating to it become zero-code targets simultaneously.
3. A chain reorg or deployment failure could leave `isBridgeToken[addr] = true` for an address that never had code.
4. The `upgradeToken` function allows the admin to point a bridge token at a new implementation; a malicious or compromised implementation could include `selfdestruct`. [6](#0-5) [7](#0-6) 

---

### Recommendation

Add an `EXTCODESIZE` guard before each direct call to a bridge token or custom minter address. A minimal helper:

```solidity
function _requireHasCode(address addr) internal view {
    uint256 size;
    assembly { size := extcodesize(addr) }
    require(size > 0, "OmniBridge: target has no code");
}
```

Call this before `BridgeToken(tokenAddress).burn(...)`, `IBridgeToken(payload.tokenAddress).mint(...)`, and `ICustomMinter(...).mint/burn(...)`. Alternatively, route all token interactions through OpenZeppelin's `SafeERC20` or a wrapper that performs the existence check, consistent with the non-bridge-token paths that already use `SafeERC20`. [8](#0-7) 

---

### Proof of Concept

1. A bridge token `T` is deployed and registered: `isBridgeToken[T] = true`, `ethToNearToken[T] = "token.near"`.
2. The implementation contract behind `T`'s UUPS proxy is selfdestructed (or `T` itself is destroyed on a pre-EIP-6780 chain).
3. Attacker calls `initTransfer(T, 1_000_000e18, 0, 0, "attacker.near", "")`.
4. `isBridgeToken[T]` is `true` → enters the bridge-token branch.
5. `BridgeToken(T).burn(attacker, 1_000_000e18)` → CALL to zero-code address → EVM returns `(true, "")` → Solidity sees void return, no revert.
6. `InitTransfer` event emitted with `amount = 1_000_000e18`.
7. Relayer submits proof to NEAR; NEAR mints `1_000_000e18` tokens to `attacker.near`.
8. Attacker holds 1,000,000 bridged tokens on NEAR having burned nothing on EVM. [9](#0-8) [10](#0-9)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L10-10)
```text
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L160-194)
```text

        // slither-disable-next-line reentrancy-no-eth
        address bridgeTokenProxy = address(
            new ERC1967Proxy(
                tokenImplementationAddress,
                abi.encodeWithSelector(
                    BridgeToken.initialize.selector,
                    metadata.name,
                    metadata.symbol,
                    decimals
                )
            )
        );

        deployTokenExtension(
            metadata.token,
            bridgeTokenProxy,
            decimals,
            metadata.decimals
        );

        emit BridgeTypes.DeployToken(
            bridgeTokenProxy,
            metadata.token,
            metadata.name,
            metadata.symbol,
            decimals,
            metadata.decimals
        );

        isBridgeToken[address(bridgeTokenProxy)] = true;
        ethToNearToken[address(bridgeTokenProxy)] = metadata.token;
        nearToEthToken[metadata.token] = address(bridgeTokenProxy);

        return bridgeTokenProxy;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-288)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L404-412)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-437)
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
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L559-566)
```text
    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }
```

**File:** evm/src/common/IBridgeToken.sol (L5-13)
```text
    function mint(address account, uint256 value) external;

    function mint(
        address account,
        uint256 value,
        bytes memory message
    ) external;

    function burn(address account, uint256 value) external;
```
