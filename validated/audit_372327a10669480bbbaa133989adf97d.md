### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` uses the caller-supplied `amount` parameter — not the actual received balance — in the `InitTransfer` event and Wormhole message. For fee-on-transfer ERC20 tokens, the bridge receives less than `amount`, but NEAR credits the user the full `amount`, permanently undercollateralizing the EVM-side escrow.

### Finding Description

In `OmniBridge.initTransfer`, the native-token path (tokens that are neither bridge-minted nor custom-minter-managed) performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // nominal, caller-supplied
);
``` [1](#0-0) 

Immediately after, the same nominal `amount` is emitted in the `InitTransfer` event:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // NOT the actual received balance
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

For `OmniBridgeWormhole`, the same nominal `amount` is also encoded into the Wormhole VAA payload:

```solidity
Borsh.encodeUint128(amount),
``` [3](#0-2) 

The bridge's own security invariant states that the `InitTransfer` event is the **sole source of truth** for the NEAR side to reconstruct the transfer. [4](#0-3) 

For fee-on-transfer tokens, `safeTransferFrom` delivers `amount - transfer_fee` to the bridge, but the event/VAA records `amount`. NEAR therefore credits the user `amount` tokens while the bridge only holds `amount - transfer_fee`. No balance-difference check is performed anywhere between the transfer and the event emission.

### Impact Explanation

**Critical — escrow mis-accounting leading to permanent freezing/loss of bridged funds.**

Each deposit of a fee-on-transfer token inflates the NEAR-side credit by exactly the token's transfer fee. When users later bridge back, `finTransfer` attempts to release the full credited `amount`:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount   // over-credited amount
);
``` [5](#0-4) 

The bridge's EVM escrow is progressively undercollateralized. Eventually, honest users who deposited fee-on-transfer tokens cannot withdraw, and the shortfall can be covered only by draining other users' funds — a direct loss of bridged assets.

### Likelihood Explanation

The `else` branch at line 406–412 is permissionless: any ERC20 token that is not registered as a bridge token or custom-minter token falls into it. [6](#0-5) 

Fee-on-transfer tokens exist on mainnet (e.g., tokens with configurable transfer taxes). An attacker can also deploy their own fee-on-transfer ERC20, bridge it to NEAR to receive an inflated credit, then bridge back to drain whatever reserves the bridge holds for that token. No privileged access is required; only a standard `initTransfer` call is needed.

### Recommendation

Replace the nominal `amount` with the actual received balance by measuring the balance difference around the `safeTransferFrom` call:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived (cast to uint128) in the event and Wormhole payload
```

Apply the same fix in `OmniBridgeWormhole.initTransferExtension` so the Wormhole VAA encodes the actual received amount, not the nominal one.

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token `FoT` with a 1% transfer fee on any supported EVM chain (e.g., Arbitrum, which uses `OmniBridgeWormhole`).
2. Call `OmniBridge.initTransfer(FoT, 1_000_000, 0, nativeFee, nearRecipient, "")`.
3. Bridge receives `990_000` tokens; event emits `amount = 1_000_000`.
4. NEAR parses the Wormhole VAA and credits `nearRecipient` with `1_000_000` FoT-equivalent tokens.
5. `nearRecipient` initiates a return transfer of `1_000_000` tokens to EVM.
6. `finTransfer` attempts `safeTransfer(recipient, 1_000_000)` but the bridge only holds `990_000` — either the call reverts (freezing funds) or it succeeds by consuming `10_000` tokens belonging to other depositors.
7. Repeat to drain the bridge escrow.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L136-136)
```text
            Borsh.encodeUint128(amount),
```

**File:** evm/CLAUDE.md (L33-33)
```markdown
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
```
