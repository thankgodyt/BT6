Audit Report

## Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`OmniBridge.initTransfer` accepts arbitrary ERC-20 tokens via `safeTransferFrom` but emits the caller-supplied `amount` — not the actual tokens received — in the `InitTransfer` event and passes it into the Wormhole VAA payload. For fee-on-transfer tokens, the bridge holds fewer tokens than the cross-chain message records, causing NEAR to credit more than the EVM escrow holds. Each such transfer grows the deficit until `finTransfer` reverts for the last users, permanently freezing their funds.

## Finding Description
In the `else` branch of `initTransfer` (reached when the token is neither a bridge token nor a custom-minter token), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not verified received amount
);
``` [1](#0-0) 

No balance snapshot is taken before or after this call. The contract immediately passes the unverified `amount` to `initTransferExtension` and then emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← user-supplied, not actual received
    ...
);
``` [2](#0-1) 

In `OmniBridgeWormhole.initTransferExtension`, the same unverified `amount` is encoded directly into the Wormhole VAA payload:

```solidity
Borsh.encodeUint128(amount),   // ← same unverified value
``` [3](#0-2) 

The `InitTransfer` event and the VAA are the authoritative cross-chain messages consumed by NEAR to credit the recipient. NEAR mints or unlocks `amount` tokens, while the EVM escrow only holds `amount - fee_amount`.

When users bridge back, `finTransfer` attempts to release the full recorded amount:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount   // ← inflated amount from NEAR record
);
``` [4](#0-3) 

The bridge will eventually be unable to honor withdrawals, permanently freezing the last users' funds.

## Impact Explanation
This is a **Critical** escrow mis-accounting impact: "Balance manipulation, escrow mis-accounting, fee mis-accounting... that changes user or protocol balances." Each `initTransfer` with a fee-on-transfer token inflates NEAR-side accounting relative to EVM-side escrow. The deficit is permanent and cumulative — it cannot be corrected without an admin intervention or contract upgrade. The last users to withdraw will have their funds permanently frozen in the bridge.

## Likelihood Explanation
The entry path is fully permissionless. `logMetadata` has no access control:

```solidity
function logMetadata(address tokenAddress) external payable {
``` [5](#0-4) 

Any unprivileged user can register any ERC-20 token and then call `initTransfer` with it. Fee-on-transfer tokens exist on mainnet (e.g., PAXG, STA, tokens with dynamic fees). No special privilege, victim mistake, or external collusion is required. Likelihood is **Medium** (requires a fee-on-transfer token to be bridged, but the path is entirely open to any user).

## Recommendation
Capture the contract's token balance before and after the `safeTransferFrom` call, and use the delta as the authoritative amount for the event and cross-chain message:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint128 actualReceived = uint128(IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore);
// use actualReceived instead of amount in initTransferExtension and the event
```

Apply the same fix to the `amount` passed into `initTransferExtension` (and therefore into the Wormhole VAA in `OmniBridgeWormhole`). [6](#0-5) 

## Proof of Concept

1. Deploy or identify a mainnet ERC-20 token `FeeToken` that charges a 1% fee on every `transferFrom`.
2. Call `OmniBridge.logMetadata(address(FeeToken))` — permissionless, no admin required.
3. Wait for NEAR to register the token metadata.
4. Call `OmniBridge.initTransfer(address(FeeToken), 1000e18, 0, 0, "alice.near", "")`.
   - `safeTransferFrom` moves `1000e18` from caller; bridge receives `990e18` (1% fee deducted).
   - `InitTransfer` event emits `amount = 1000e18`.
   - Wormhole VAA encodes `amount = 1000e18`.
5. NEAR relayer observes the event/VAA and mints `1000e18` wrapped `FeeToken` to `alice.near`.
6. Alice bridges back: NEAR burns `1000e18` and signs a `finTransfer` for `1000e18`.
7. `finTransfer` on EVM calls `safeTransfer(alice, 1000e18)` but the bridge only holds `990e18` — the call reverts, Alice's funds are permanently frozen.

Repeating step 4 many times accelerates the deficit until the bridge is fully insolvent for `FeeToken`. A fuzz/invariant test asserting `escrow_balance >= sum(InitTransfer.amount) - sum(FinTransfer.amount)` for the `else` branch would reproduce this finding.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-224)
```text
    function logMetadata(address tokenAddress) external payable {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-425)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L136-137)
```text
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
```
