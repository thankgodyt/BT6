### Title
Fee-on-Transfer Token Balance Mis-Accounting in `initTransfer` Enables Bridge Insolvency — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` uses the caller-supplied `amount` parameter directly in the emitted `InitTransfer` event without measuring the actual tokens received by the contract. For fee-on-transfer ERC20 tokens, the contract receives fewer tokens than `amount`, but the NEAR side processes the event and mints/releases the full `amount`, creating an unbounded insolvency gap in the bridge's EVM escrow.

---

### Finding Description

In `OmniBridge.initTransfer`, when `tokenAddress` is a plain ERC20 (not a bridge token or custom minter), the function executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied
);
```

and then immediately emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-supplied value, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) 

The contract never measures the balance delta. For a fee-on-transfer token (one that deducts a percentage on every `transferFrom`), the contract receives `amount - transferFee` tokens, but the `InitTransfer` event records `amount`. The NEAR bridge reads this event and credits the full `amount` to the recipient on NEAR, while the EVM escrow is short by `transferFee` per call.

This is the direct analog of the TreehouseRouter bug: instead of returning `balanceOf(address(this))` (which inflates the value with accidentally deposited tokens), `initTransfer` emits the caller-controlled `amount` (which inflates the value relative to what was actually escrowed). In both cases, the accounting value diverges from the true escrowed balance, and the divergence is exploitable.

---

### Impact Explanation

Every `initTransfer` call with a fee-on-transfer token causes the EVM bridge to hold fewer tokens than the NEAR side believes are locked. Legitimate users bridging back from NEAR to EVM will find the EVM contract unable to release their tokens. An attacker can deliberately repeat this to drain the bridge's EVM reserves for any token that charges a transfer fee, resulting in permanent loss of bridged funds for honest users.

This falls squarely within: *"Balance manipulation, escrow mis-accounting … that changes user or protocol balances."*

---

### Likelihood Explanation

`initTransfer` is a public, permissionless function — any address can call it with any ERC20 token address. The bridge does not whitelist tokens or validate that a token is fee-free before accepting it. Fee-on-transfer tokens (e.g., tokens with a built-in tax, reflection tokens, or tokens with a configurable fee) are a well-known ERC20 variant. An attacker can deploy or use an existing fee-on-transfer token to exploit this systematically.

---

### Recommendation

Measure the actual received amount using a balance snapshot before and after the transfer, and use that value in the event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = uint128(IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore);
require(actualReceived == amount, "Fee-on-transfer tokens not supported");
```

Alternatively, explicitly document and enforce that fee-on-transfer tokens are not supported by reverting if `actualReceived != amount`.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token `FeeToken` that deducts 1% on every `transferFrom`.
2. Call `OmniBridge.initTransfer(address(FeeToken), 1000, 0, 0, "near:alice.near", "")`.
3. `safeTransferFrom` transfers 990 tokens to the bridge (1% fee deducted by the token contract).
4. The `InitTransfer` event is emitted with `amount = 1000`.
5. A relayer submits proof of this event to the NEAR bridge.
6. The NEAR bridge mints 1000 `FeeToken`-equivalent tokens to `alice.near`.
7. The EVM bridge now holds 990 tokens but has issued a claim for 1000 — a 10-token deficit.
8. Repeating this 100 times with `amount = 1000` creates a 1000-token deficit; the bridge cannot honour all redemptions. [2](#0-1)

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
