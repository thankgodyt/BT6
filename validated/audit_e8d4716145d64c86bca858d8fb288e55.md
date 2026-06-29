### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer()` Inflates Bridged Amount, Draining EVM Escrow - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer()` uses the caller-supplied `amount` parameter both for the `safeTransferFrom` pull and for the emitted `InitTransfer` event. When a fee-on-transfer ERC20 token is used, the contract receives fewer tokens than `amount`, but the event records the full `amount`. NEAR finalizes the transfer for the full `amount`, minting more tokens than were actually escrowed on the EVM side. The EVM bridge escrow becomes permanently under-collateralized, causing fund loss for later withdrawers.

---

### Finding Description

In `OmniBridge.initTransfer()`, the native ERC20 lock path does:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // user-supplied; actual received = amount - fee
);
``` [1](#0-0) 

Immediately after, the function emits the event using the original `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // inflated; not actual received balance
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

No balance-before/balance-after check is performed. The `InitTransfer` event is the on-chain proof that a relayer submits to NEAR to finalize the inbound transfer. NEAR's `fin_transfer` mints or unlocks exactly `amount` tokens to the recipient. [3](#0-2) 

The same pattern exists in the Starknet `init_transfer`:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
```

followed by emitting `InitTransfer` with the original `amount`. [4](#0-3) [5](#0-4) 

The `customMinters` path has a secondary variant: `safeTransferFrom` to the custom minter address, then `burn(tokenAddress, amount)` is called with the original `amount` — if the minter received less due to fee, the burn call will revert or mis-account. [6](#0-5) 

---

### Impact Explanation

Each fee-on-transfer deposit creates a deficit of `fee_amount` tokens in the EVM bridge escrow. NEAR mints the full `amount` to the recipient. When those NEAR-side tokens are later bridged back to EVM via `finTransfer`, the bridge must release `amount` tokens but only holds `amount - fee_amount`. The deficit accumulates with every such deposit. Eventually, the bridge cannot fulfill legitimate withdrawals, causing permanent loss of bridged funds for users who deposited without fee-on-transfer tokens. This is a **Critical** escrow mis-accounting / balance manipulation impact.

---

### Likelihood Explanation

Fee-on-transfer tokens are a known ERC20 pattern (e.g., PAXG charges a fee; USDT has fee-on-transfer capability in its contract that can be activated). The bridge accepts arbitrary ERC20 tokens registered by admin. Any registered token that activates fee-on-transfer — or any future token added to the bridge that has this property — triggers the vulnerability. The attacker entry path is simply calling `initTransfer` with such a token; no special privileges are required.

---

### Recommendation

Use the balance-before/balance-after pattern to compute the actual received amount, and use that value in the event and all downstream accounting:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// Use actualReceived (cast to uint128) in the event and extension call
```

Apply the same fix to the Starknet `init_transfer` and to the `customMinters` path (check actual balance received by the custom minter before calling `burn`).

---

### Proof of Concept

1. Admin registers a fee-on-transfer ERC20 token `FeeToken` (1% fee per transfer) with the EVM OmniBridge.
2. Alice calls `initTransfer(FeeToken, 1000, 0, 0, "near:alice.near", "")`.
3. `safeTransferFrom(Alice, OmniBridge, 1000)` executes — OmniBridge receives **990** tokens (1% fee deducted).
4. `InitTransfer` event emits `amount = 1000`.
5. Relayer proves the event to NEAR; NEAR mints **1000** `FeeToken` NEAR-side tokens to Alice.
6. Alice bridges back 1000 NEAR-side tokens to EVM. NEAR burns 1000 tokens; MPC signs a `finTransfer` payload for 1000.
7. `finTransfer` on EVM calls `safeTransfer(Alice, 1000)` — but OmniBridge only holds **990** tokens. The transaction reverts, or if other users' deposits cover the deficit, Alice steals 10 tokens from the pool.
8. Repeated deposits accumulate the deficit, eventually making the bridge insolvent. [7](#0-6)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L540-543)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
```

**File:** starknet/src/omni_bridge.cairo (L304-306)
```text
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
```

**File:** starknet/src/omni_bridge.cairo (L316-330)
```text
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
