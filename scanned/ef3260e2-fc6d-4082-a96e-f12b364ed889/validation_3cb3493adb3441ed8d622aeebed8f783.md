### Title
Fee-on-Transfer Token Mis-Accounting in `initTransfer`: Emitted Amount Exceeds Actual Locked Amount — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The EVM `OmniBridge.sol` `initTransfer` function records and emits the caller-supplied `amount` parameter in the `InitTransfer` event, but the actual tokens received by the contract may be less than `amount` when a fee-on-transfer ERC-20 token is used. The NEAR side reads the emitted `amount` from the proof and mints that full value to the recipient. This creates a persistent mismatch between tokens locked on EVM and tokens minted on NEAR, enabling over-minting and eventual insolvency of the bridge's EVM escrow.

---

### Finding Description

In `OmniBridge.sol`, the non-bridge-token path of `initTransfer` executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // input parameter — not actual received amount
);
```

Immediately after, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same input parameter, not balance delta
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) 

For a fee-on-transfer ERC-20 token, `safeTransferFrom` silently delivers `amount - token_fee` to the contract while the event records `amount`. No balance-before/balance-after check is performed to derive the true received quantity.

The NEAR `fin_transfer` flow reads the `InitTransferMessage` produced by the EVM prover, which parses the `amount` field directly from the emitted event log. It then mints or unlocks exactly that `amount` to the recipient on NEAR. [2](#0-1) 

The same structural flaw exists in the Starknet bridge:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
// emits `amount` (input), not actual received
``` [3](#0-2) 

---

### Impact Explanation

Every `initTransfer` call with a fee-on-transfer token causes NEAR to mint `amount` while EVM only holds `amount - token_fee`. Over repeated transfers the EVM escrow becomes under-collateralised by the cumulative fee delta. Any user who later bridges back from NEAR to EVM will find the EVM contract unable to release the full amount, resulting in permanent loss of bridged funds for late redeemers. An attacker can deliberately amplify this by repeatedly bridging a high-fee token, draining the EVM escrow relative to the outstanding NEAR supply.

This matches the **Critical** impact class: escrow mis-accounting that changes user and protocol balances, and permanent freezing/loss of bridged funds.

---

### Likelihood Explanation

The bridge is permissionless with respect to which ERC-20 tokens can be locked — there is no on-chain whitelist enforced in `initTransfer`. Fee-on-transfer tokens (e.g., tokens with deflationary mechanics, reflection tokens, or tokens with protocol fees) are a well-established and widely deployed token class. Any user can trigger this path by calling `initTransfer` with such a token; no privileged access is required.

---

### Recommendation

Replace the fixed-`amount` transfer with a balance-delta pattern:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived in the event and all downstream accounting
emit BridgeTypes.InitTransfer(..., actualReceived, ...);
```

Apply the same fix to the Starknet `init_transfer` function. Ensure the NEAR `fin_transfer` path uses the event-recorded `actualReceived` value (which it already reads from the proof), so the fix propagates end-to-end without NEAR-side changes.

---

### Proof of Concept

1. Deploy or use any ERC-20 token that deducts a 1% fee on every `transferFrom` (e.g., a reflection token).
2. Call `OmniBridge.initTransfer(tokenAddress, 1_000_000, 0, 0, nearRecipient, "")`.
3. The contract receives `990_000` tokens; the event emits `amount = 1_000_000`.
4. A relayer submits the EVM Merkle proof to NEAR `fin_transfer`.
5. NEAR mints `1_000_000` tokens to `nearRecipient`.
6. Repeat N times. After N transfers the EVM escrow holds `N × 990_000` tokens but NEAR has minted `N × 1_000_000` — a `N × 10_000` token shortfall.
7. The first `N × 0.99` redeemers can withdraw normally; the remaining redeemers find the EVM contract insolvent.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-436)
```text
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

**File:** starknet/src/omni_bridge.cairo (L303-330)
```text
            } else {
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
