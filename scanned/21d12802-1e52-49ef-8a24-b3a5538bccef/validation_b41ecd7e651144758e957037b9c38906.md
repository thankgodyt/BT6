### Title
Fee-on-Transfer Token Balance Mismatch Causes Permanent Fund Freezing in `finTransfer` - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`initTransfer` in `OmniBridge.sol` records and emits the caller-supplied `amount` for native ERC20 tokens without verifying the actual amount received by the contract. For fee-on-transfer ERC20 tokens, the contract receives `amount - fee` but the `InitTransfer` event records `amount`. The NEAR side mints/records the full `amount`. When the reverse bridge leg executes `finTransfer`, it attempts to release the full `amount` from the EVM contract's balance, which is insufficient, causing a permanent revert and freezing all bridged funds for that token.

### Finding Description
In `initTransfer`, for native ERC20 tokens (not bridge tokens, not custom minters), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [1](#0-0) 

The function then emits `InitTransfer` with the caller-supplied `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress, currentOriginNonce,
    amount, fee, nativeFee, recipient, message
);
``` [2](#0-1) 

No balance-before/balance-after check is performed. For a fee-on-transfer token, the contract receives `amount - transfer_fee` but the event records `amount`. The NEAR bridge reads this event and mints or credits the full `amount` to the recipient.

When the reverse transfer occurs (NEAR → EVM), the NEAR MPC signs a payload containing `amount`. `finTransfer` on EVM then executes:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
``` [3](#0-2) 

The contract only holds `amount - transfer_fee` but attempts to release `amount`. `safeTransfer` reverts. There is no recovery path: the nonce is already marked used (`completedTransfers[payload.destinationNonce] = true` at line 287), so the same payload cannot be resubmitted. [4](#0-3) 

The same pattern exists in the Starknet bridge's `init_transfer` / `fin_transfer` pair: [5](#0-4) [6](#0-5) 

### Impact Explanation
For any fee-on-transfer ERC20 token registered with the bridge:
- The EVM contract permanently holds less than the sum of all `InitTransfer` amounts for that token.
- Every `finTransfer` attempting to release the full declared amount will revert.
- Bridged funds are permanently frozen in the EVM `OmniBridge` contract with no recovery mechanism, since the destination nonce is consumed on the first attempt.
- On the NEAR side, tokens have already been minted to recipients, creating an unbacked surplus relative to the EVM escrow.

This constitutes permanent freezing of bridged funds and escrow mis-accounting — both within the critical impact scope.

### Likelihood Explanation
Fee-on-transfer ERC20 tokens are a well-established token class (e.g., tokens with redistribution mechanics, certain stablecoins with configurable fees). The `initTransfer` function imposes no restriction on which ERC20 tokens can be used — any address passes the `else` branch. A single user bridging such a token triggers the irreversible accounting divergence. No privileged access is required; the entry point is fully public.

### Recommendation
Record the actual received amount using a balance-before/balance-after pattern:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(received == amount, "FeeOnTransferNotSupported");
```

Alternatively, explicitly document and enforce that fee-on-transfer tokens are unsupported by adding a token allowlist or a registry check before the `safeTransferFrom` call. Apply the same fix to the Starknet `init_transfer`.

### Proof of Concept
1. Deploy or identify a fee-on-transfer ERC20 token `T` (e.g., 5% fee on every transfer) that is registered with the NEAR Omni Bridge.
2. Call `OmniBridge.initTransfer(T, 1000, 0, 0, "near:alice.near", "")`.
   - `safeTransferFrom` moves 1000 from caller; contract receives 950 (5% fee).
   - `InitTransfer` event emits `amount = 1000`.
3. NEAR relayer submits the proof; NEAR bridge mints 1000 NEAR-side tokens to `alice.near`.
4. Alice bridges back: NEAR burns 1000 tokens, MPC signs a payload with `amount = 1000`.
5. Relayer calls `OmniBridge.finTransfer(sig, payload)` on EVM.
   - `completedTransfers[nonce] = true` is set.
   - `safeTransfer(alice_evm, 1000)` reverts — contract only holds 950.
6. The nonce is consumed; the payload can never be resubmitted. Alice's 1000 NEAR-side tokens are burned, and the 950 EVM tokens are permanently locked in `OmniBridge` with no withdrawal path.

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-411)
```text
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
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
