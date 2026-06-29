### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` records and emits the caller-supplied `amount` parameter in the `InitTransfer` event without verifying that the contract actually received that amount. For fee-on-transfer ERC20 tokens, the contract receives less than `amount`, but the event—which the NEAR side uses to mint or unlock tokens—claims the full `amount`. This lets an attacker drain the bridge's EVM-side reserves by repeatedly bridging a fee-on-transfer token.

### Finding Description

In `initTransfer`, the non-bridge, non-custom-minter ERC20 path calls:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [1](#0-0) 

Immediately after, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,   // ← user-supplied, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

No balance-before/balance-after check is performed. For a fee-on-transfer ERC20 (one that deducts a percentage on every transfer), `safeTransferFrom` succeeds and returns `true`, but `address(this)` receives `amount - fee_deducted`. The emitted event still carries the full `amount`.

The NEAR `omni-bridge` contract consumes this event via a prover and uses the emitted `amount` to mint or unlock tokens for the recipient:

```rust
// ft_on_transfer / fin_transfer_callback uses transfer_message.amount
// which is sourced directly from the InitTransfer event's `amount` field
let transfer_message = TransferMessage {
    amount,   // ← taken from the event
    ...
};
``` [3](#0-2) 

There is no analogous balance check on the NEAR side either; it trusts the event value entirely.

### Impact Explanation

**Critical — escrow mis-accounting / unauthorized minting.**

Each `initTransfer` call with a fee-on-transfer token causes the bridge to mint or release more tokens on NEAR than were actually locked on EVM. The EVM vault is undercollateralized by the fee amount per transfer. An attacker who repeatedly bridges such a token can eventually exhaust the EVM-side reserves: when legitimate users later try to withdraw (via `finTransfer` on EVM), the vault holds insufficient tokens to cover all outstanding claims, resulting in permanent loss of bridged funds.

### Likelihood Explanation

**Medium.** The `else` branch in `initTransfer` accepts any ERC20 token that is not a registered bridge token or custom minter. Fee-on-transfer tokens exist in production (e.g., tokens with reflection mechanics or protocol fees). Once such a token is registered with the bridge via `logMetadata`, any unprivileged user can exploit this path. The attacker needs no special role; they only need to hold the fee-on-transfer token and call `initTransfer`.

### Recommendation

Measure the actual received amount using a balance-before/balance-after pattern and use that value in the event:

```solidity
} else {
    uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
    require(received == amount, "fee-on-transfer token not supported");
    // or: use `received` as the canonical amount in the event
}
```

Alternatively, explicitly document and enforce that fee-on-transfer tokens are not supported, and add a registry check that rejects them at `logMetadata` time.

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token `FeeToken` that deducts 1% on every `transferFrom`.
2. Register `FeeToken` with the bridge via `logMetadata` (or use an already-registered one).
3. Approve the bridge for `1,000,000` units and call `initTransfer(FeeToken, 1_000_000, 0, 0, "near:attacker.near", "")`.
4. The bridge receives `990,000` tokens (1% fee deducted), but emits `InitTransfer(..., amount=1_000_000, ...)`.
5. The NEAR prover verifies the event and the NEAR `omni-bridge` mints `1,000,000` omni-tokens to `attacker.near`.
6. Attacker now holds `1,000,000` NEAR-side tokens backed by only `990,000` EVM-side tokens.
7. Repeat until the EVM vault is drained; subsequent legitimate withdrawals fail. [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L540-553)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
```
