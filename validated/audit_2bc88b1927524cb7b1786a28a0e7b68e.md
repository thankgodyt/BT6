Audit Report

## Title
Fee-on-Transfer Token Balance Mismatch Causes Permanent Fund Freezing in `initTransfer` / `finTransfer` - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

## Summary
`initTransfer` in `OmniBridge.sol` records and emits the caller-supplied `amount` for native ERC20 tokens without verifying the actual amount received. For fee-on-transfer tokens, the contract receives `amount - fee` but the `InitTransfer` event records `amount`, causing the NEAR side to mint the full `amount`. When the reverse leg executes `finTransfer`, it attempts to release the full `amount` from a contract that only holds `amount - fee`, causing every `finTransfer` call to revert permanently with no on-chain recovery path.

## Finding Description
In `initTransfer`, the `else` branch for native ERC20 tokens (not bridge tokens, not custom minters) executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [1](#0-0) 

No balance-before/balance-after check is performed. The function then emits `InitTransfer` with the caller-supplied `amount`: [2](#0-1) 

For a fee-on-transfer token, the contract receives `amount - transfer_fee` but the event records `amount`. The NEAR relayer reads this event and mints the full `amount` to the recipient on NEAR.

When the reverse transfer occurs (NEAR → EVM), `finTransfer` executes:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
``` [3](#0-2) 

The contract only holds `amount - transfer_fee` but attempts to release `amount`. `safeTransfer` reverts, rolling back the entire transaction atomically — including the `completedTransfers` write at line 287. The nonce is therefore not permanently consumed per call, but the contract can **never** accumulate enough tokens to satisfy the transfer: every `finTransfer` attempt will revert indefinitely. The contract has no admin rescue or emergency-withdrawal function for ERC20 tokens; the only egress path for native ERC20 tokens is `finTransfer` itself. [4](#0-3) 

The same pattern exists in the Starknet bridge: `init_transfer` calls `transfer_from` with the declared `amount` and emits it without a balance check, while `fin_transfer` calls `transfer` with `payload.amount`. [5](#0-4) [6](#0-5) 

## Impact Explanation
This constitutes **permanent freezing of bridged funds** and **escrow mis-accounting**, both within the critical impact scope. The EVM contract permanently holds less than the sum of all `InitTransfer` amounts for the affected token. Every `finTransfer` for that token's declared amount will revert indefinitely. On the NEAR side, tokens have already been minted to recipients, creating an unbacked surplus relative to the EVM escrow. There is no on-chain recovery mechanism: no rescue function, no adjustable payload, and no alternative egress for native ERC20 tokens held by the contract.

## Likelihood Explanation
Fee-on-transfer ERC20 tokens are a well-established token class. The `logMetadata` function is permissionless (no access control), allowing any token to be registered with the NEAR bridge. The `initTransfer` `else` branch imposes no allowlist or token-type restriction — any ERC20 address reaches it. A single unprivileged user bridging a fee-on-transfer token triggers the irreversible accounting divergence. No privileged access is required. [7](#0-6) [8](#0-7) 

## Recommendation
Use a balance-before/balance-after pattern and reject fee-on-transfer tokens explicitly:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(received == amount, "FeeOnTransferNotSupported");
```

Alternatively, enforce a token allowlist or registry check before the `safeTransferFrom` call to explicitly exclude fee-on-transfer tokens. Apply the equivalent fix to the Starknet `init_transfer`.

## Proof of Concept
1. Deploy or identify a fee-on-transfer ERC20 token `T` (e.g., 5% fee on every transfer).
2. Call `OmniBridge.logMetadata(T)` to register `T` with the NEAR bridge (permissionless).
3. Wait for the NEAR side to deploy a bridge representation of `T`.
4. Call `OmniBridge.initTransfer(T, 1000, 0, 0, "near:alice.near", "")`.
   - `safeTransferFrom` moves 1000 from caller; contract receives 950.
   - `InitTransfer` event emits `amount = 1000`.
5. NEAR relayer submits the proof; NEAR bridge mints 1000 NEAR-side tokens to `alice.near`.
6. Alice bridges back: NEAR burns 1000 tokens, MPC signs a payload with `amount = 1000`.
7. Relayer calls `OmniBridge.finTransfer(sig, payload)` on EVM.
   - `safeTransfer(alice_evm, 1000)` reverts — contract only holds 950.
   - The entire transaction reverts atomically; the nonce is not consumed.
8. Every subsequent `finTransfer` attempt reverts for the same reason. The 950 EVM tokens are permanently locked in `OmniBridge` with no withdrawal path, while 1000 NEAR-side tokens have already been minted to Alice.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-231)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-354)
```text
        } else {
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

**File:** starknet/src/omni_bridge.cairo (L259-263)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
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
