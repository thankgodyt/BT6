Audit Report

## Title
Fee-on-Transfer Token Mis-Accounting in `initTransfer`: Emitted Amount Exceeds Actual Locked Amount — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
The `initTransfer` function in `OmniBridge.sol` transfers tokens using the caller-supplied `amount` parameter and immediately emits that same `amount` in the `InitTransfer` event without measuring the actual balance delta. For fee-on-transfer ERC-20 tokens, the contract receives `amount - token_fee` while the event records `amount`. The NEAR side reads the emitted `amount` from the proof and mints or releases that full value, creating a persistent under-collateralization of the EVM escrow relative to outstanding NEAR-side supply.

## Finding Description
In the non-bridge-token, non-custom-minter path of `initTransfer`, the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied input
);
``` [1](#0-0) 

Immediately after, without any balance-before/balance-after measurement, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-supplied input, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

There is no whitelist check in `initTransfer` — any ERC-20 address is accepted in the non-bridge-token branch. [3](#0-2) 

On the NEAR side, `fin_transfer` calls `send_tokens` with `transfer_message.amount_without_fee()`, which is derived directly from the `amount` field parsed out of the emitted event log — the inflated value, not the actual received quantity. [4](#0-3) 

The identical structural flaw exists in the Starknet bridge: `transfer_from` is called with `amount`, and the `InitTransfer` event is emitted with the same `amount` without a balance delta check. [5](#0-4) 

## Impact Explanation
Every `initTransfer` call with a fee-on-transfer token causes NEAR to mint `amount` while the EVM contract only holds `amount - token_fee`. Over repeated transfers, the EVM escrow becomes under-collateralized by the cumulative fee delta. When users later bridge back from NEAR to EVM, the EVM contract cannot release the full amount for all redeemers — late redeemers suffer permanent loss of bridged funds. This directly matches the Critical allowed impact: **escrow mis-accounting that changes user and protocol balances**, and **permanent freezing/loss of bridged funds**.

## Likelihood Explanation
The `initTransfer` function is permissionless and accepts any ERC-20 token address with no on-chain whitelist enforcement. Fee-on-transfer tokens (reflection tokens, deflationary tokens, tokens with protocol transfer fees) are a well-established and widely deployed token class. No privileged access is required; any external user can trigger this path by calling `initTransfer` with such a token. The attack is repeatable and cumulative, amplifying the shortfall with each transfer.

## Recommendation
Replace the fixed-`amount` transfer with a balance-delta pattern in `OmniBridge.sol`:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived in the event and all downstream accounting
emit BridgeTypes.InitTransfer(..., uint128(actualReceived), ...);
```

Apply the same balance-delta fix to the Starknet `init_transfer` function. The NEAR `fin_transfer` path already reads the event-recorded value from the proof, so it will automatically use the corrected `actualReceived` value without requiring NEAR-side changes.

## Proof of Concept
1. Deploy or use any ERC-20 token that deducts a 1% fee on every `transferFrom` (e.g., a reflection token).
2. Call `OmniBridge.initTransfer(tokenAddress, 1_000_000, 0, 0, nearRecipient, "")`.
3. The contract receives `990_000` tokens; the `InitTransfer` event records `amount = 1_000_000`.
4. A relayer submits the EVM proof to NEAR `fin_transfer`.
5. NEAR mints `1_000_000` tokens to `nearRecipient` (via `amount_without_fee()` on the inflated value).
6. Repeat N times. After N transfers the EVM escrow holds `N × 990_000` tokens but NEAR has minted `N × 1_000_000` — a cumulative `N × 10_000` token shortfall.
7. The first `~N × 0.99` redeemers can withdraw normally from EVM; the remaining redeemers find the EVM contract insolvent and suffer permanent loss.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L1957-1966)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
```

**File:** starknet/src/omni_bridge.cairo (L304-330)
```text
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```
