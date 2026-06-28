### Title
Fee-on-Transfer Token Escrow Over-Crediting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` emits an `InitTransfer` event crediting the user-supplied `amount` without verifying how many tokens the contract actually received. For fee-on-transfer ERC-20 tokens, the bridge receives `amount - transfer_fee` but the event records `amount`. NEAR relayers use the emitted event value to mint tokens on the destination chain, creating unbacked supply.

### Finding Description

In `OmniBridge.initTransfer`, when the token is a plain ERC-20 (not a bridge token or custom minter), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied value
);
``` [1](#0-0) 

Immediately after, the contract emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // same caller-supplied value, not actual received amount
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

There is no balance-before / balance-after check to confirm the actual tokens received. For a fee-on-transfer token (e.g., 1% fee), if a user calls `initTransfer` with `amount = 1000`, the bridge vault holds only `990` tokens, but the `InitTransfer` event records `amount = 1000`.

The NEAR bridge contract processes this event and mints `1000` tokens to the recipient on NEAR. The EVM escrow is now undercollateralized by `10` tokens. Every subsequent `initTransfer` with the same token widens the deficit. When those NEAR tokens are eventually bridged back, the EVM bridge cannot honor the full redemption.

The `finTransfer` path on EVM has a symmetric issue: `safeTransfer(payload.recipient, payload.amount)` sends the full signed `amount` from escrow, but if the token charges a fee on transfer, the recipient receives less than `payload.amount` while the escrow is debited the full amount, draining the vault faster than tokens enter it. [3](#0-2) 

### Impact Explanation

**Critical — escrow mis-accounting / unbacked token minting.**

For `initTransfer`: the NEAR bridge mints more tokens than are locked in the EVM vault. Repeated transfers create an ever-growing undercollateralization. When users bridge back, the EVM vault cannot pay out, causing permanent loss of funds for later redeemers.

For `finTransfer`: the EVM vault is debited `payload.amount` but the recipient receives less, draining the vault and causing loss of bridged funds for users.

### Likelihood Explanation

Any unprivileged user can call `initTransfer` with a fee-on-transfer ERC-20 token that has been registered with the bridge (via `logMetadata` + NEAR-side `deploy_token`). No special role or admin action is required beyond the token being supported. Fee-on-transfer tokens (e.g., PAXG, STA, tokens with reflection mechanics) are a well-known token class. The entry path is fully permissionless.

### Recommendation

Record the contract's token balance before and after `safeTransferFrom` in `initTransfer`, and use the difference as the canonical `amount` for the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived in the InitTransfer event instead of amount
```

Similarly, in `finTransfer`, record the recipient's balance before and after `safeTransfer` and revert if the actual received amount is less than `payload.amount` (or adjust the signed payload to reflect net-of-fee amounts).

### Proof of Concept

1. A fee-on-transfer ERC-20 token `FOT` (2% fee) is registered with the bridge via `logMetadata` on EVM and `deploy_token` on NEAR.
2. Alice calls `initTransfer(FOT, 1000, 0, 0, "alice.near", "")`.
3. `safeTransferFrom` moves `1000` FOT from Alice; the token's fee mechanism retains `20`, so the bridge vault receives `980`.
4. `InitTransfer` event is emitted with `amount = 1000`.
5. A NEAR relayer submits the proof; NEAR's `fin_transfer` mints `1000` FOT-wrapped tokens to `alice.near`.
6. The EVM vault holds `980` FOT but NEAR has `1000` in circulation — a `20`-token deficit.
7. Repeating step 2–6 one hundred times creates a `2000`-token deficit. The last redeemers who bridge back cannot be paid, losing their funds permanently. [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-436)
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
```
