### Title
Fee-on-Transfer Token Escrow Under-Collateralization in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` pulls `amount` tokens from the caller via `safeTransferFrom` and immediately emits an `InitTransfer` event recording `amount` as the bridged value — without comparing the contract's pre- and post-transfer balance. For fee-on-transfer ERC-20 tokens the contract actually receives `amount − transfer_fee`, yet the NEAR side reads the emitted `amount` and mints the full `amount` to the recipient. The EVM escrow is permanently under-collateralized by the transfer fee on every such deposit.

---

### Finding Description

In `initTransfer` the non-bridge-token, non-custom-minter branch executes:

```solidity
// OmniBridge.sol lines 407-411
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
```

Immediately after, the function emits:

```solidity
// OmniBridge.sol lines 427-436
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,   // ← caller-supplied, not actual received balance
    fee,
    nativeFee,
    recipient,
    message
);
```

No snapshot of `IERC20(tokenAddress).balanceOf(address(this))` is taken before or after the pull. For a fee-on-transfer token the contract holds `amount − transfer_fee` but the event asserts `amount`. The NEAR prover accepts the event at face value and mints the full `amount` on NEAR.

The identical pattern exists in the Starknet bridge:

```cairo
// starknet/src/omni_bridge.cairo lines 304-306
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
// ... emits InitTransfer { amount, ... } with no balance delta check
```

---

### Impact Explanation

**Critical — escrow mis-accounting / loss of bridged funds.**

Each `initTransfer` call with a fee-on-transfer token creates a deficit of `transfer_fee` tokens in the EVM escrow. NEAR mints the full `amount`, so the total NEAR-side supply of that token exceeds the EVM-side collateral. When any user later bridges back (NEAR burns `amount`, EVM must release `amount`), the EVM bridge cannot satisfy the full withdrawal once the cumulative deficit exceeds its reserves. Legitimate users lose funds they cannot recover.

An attacker who controls or deploys a fee-on-transfer ERC-20 and registers it through the normal bridge token-mapping flow can amplify this deficit at will, draining the EVM escrow of that token entirely while holding an inflated NEAR balance.

---

### Likelihood Explanation

**Low-to-medium.** The bridge does not whitelist arbitrary ERC-20 tokens; a token must have a registered `ethToNearToken` mapping for the NEAR side to finalize. However, the registration path is permissionless for token deployers (any party can deploy a token and log its metadata). A malicious or inadvertently fee-charging token that passes registration is sufficient to trigger the bug. Real-world fee-on-transfer tokens (e.g., STA, PAXG in certain configurations, reflection tokens) exist and could be bridged if registered.

---

### Recommendation

Record the contract's token balance before and after the `safeTransferFrom` call and use the delta — not the caller-supplied `amount` — as the canonical bridged value in the emitted event and in all downstream accounting:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use `received` (cast to uint128 with overflow check) in the event and extension call
```

Apply the same fix to the Starknet `init_transfer` in `starknet/src/omni_bridge.cairo`.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC-20 `FeeToken` that deducts 10 % on every `transferFrom`.
2. Register `FeeToken` in the bridge's `ethToNearToken` mapping (permissionless metadata log).
3. Approve `OmniBridge` for `1 000 FeeToken` and call:
   ```solidity
   bridge.initTransfer(address(feeToken), 1000, 0, 0, "alice.near", "");
   ```
4. Bridge receives `900 FeeToken` (10 % fee deducted by the token).
5. `InitTransfer` event records `amount = 1000`.
6. NEAR prover reads the event; NEAR contract mints `1000` omni-FeeToken to `alice.near`.
7. Alice bridges back: NEAR burns `1000`, EVM bridge attempts `safeTransfer(alice, 1000)` — but only holds `900` → transfer reverts or drains other depositors' funds.
8. Repeat step 3–6 N times to exhaust the EVM escrow entirely. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
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
