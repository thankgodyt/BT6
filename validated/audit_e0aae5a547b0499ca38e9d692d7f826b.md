### Title
EVM `initTransfer` records user-specified `amount` in event without verifying actual received balance, enabling escrow undercollateralization via fee-on-transfer tokens - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

The `initTransfer` function in `OmniBridge.sol` emits the caller-supplied `amount` in the `InitTransfer` event without verifying that the bridge actually received that amount. For fee-on-transfer ERC20 tokens, the bridge receives less than `amount`, but the NEAR side reads the event and credits the full `amount` to the recipient. This is a direct analog to the external report's escrow mis-accounting class: a stored/recorded value (the event amount) diverges from the actual token balance held in escrow, causing the bridge to become undercollateralized.

---

### Finding Description

In `OmniBridge.sol`, the `initTransfer` function handles non-bridge, non-custom ERC20 tokens with the following path:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
```

followed immediately by:

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
``` [1](#0-0) 

The bridge performs no before/after balance check. For a fee-on-transfer ERC20 token, `safeTransferFrom` succeeds but the bridge receives `amount - transfer_fee` tokens. The event, however, records the full user-specified `amount`. The NEAR side relies exclusively on this event to determine how many tokens to credit:

> "The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees." [2](#0-1) 

The NEAR `fin_transfer` path mints or releases `amount` tokens to the recipient based on the event data. The bridge's EVM escrow is now undercollateralized by `transfer_fee` per transaction. [3](#0-2) 

The same pattern exists in `initTransfer1155` and in the Starknet `init_transfer`: [4](#0-3) 

---

### Impact Explanation

Each `initTransfer` call with a fee-on-transfer token creates a deficit in the bridge's EVM escrow. The NEAR side mints omni-tokens equal to the full `amount`; the EVM bridge holds only `amount - fee`. When users later bridge back from NEAR to EVM, the NEAR side burns their omni-tokens and the EVM bridge attempts to release the full credited amount via `safeTransfer(payload.recipient, payload.amount)`: [5](#0-4) 

The bridge cannot cover the full liability. The last users to bridge back lose their funds. This is a direct loss of bridged funds — Critical impact under the allowed scope ("escrow mis-accounting… that changes user or protocol balances").

---

### Likelihood Explanation

Fee-on-transfer ERC20 tokens exist on mainnet (e.g., tokens with deflationary mechanics). The bridge does not whitelist tokens or enforce any fee-on-transfer guard. Any unprivileged user can call `initTransfer` with such a token. The constraint is that the token must be registered/bound on the NEAR side for the NEAR `fin_transfer` to process the event; however, once a fee-on-transfer token is bound, every subsequent `initTransfer` call silently accumulates a deficit. No admin compromise or special role is required.

---

### Recommendation

Add a before/after balance check for the non-bridge, non-custom ERC20 path in `initTransfer` and use the actual received amount in the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(uint128(actualReceived) == amount, "FeeOnTransferNotSupported");
```

Alternatively, explicitly document and enforce that fee-on-transfer tokens are unsupported by reverting on any token whose actual received amount differs from `amount`.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 token `FoT` with a 10% transfer fee. Register/bind `FoT` on the NEAR side so the bridge will process `InitTransfer` events for it.
2. Call `OmniBridge.initTransfer(FoT, 1000, 0, 0, "victim.near", "")`.
3. `safeTransferFrom` moves 1000 tokens from the caller; the token contract retains 100 as a fee; the bridge receives 900.
4. The `InitTransfer` event records `amount = 1000`.
5. The NEAR relayer submits the proof; `fin_transfer` mints 1000 omni-FoT tokens to `victim.near`.
6. The EVM bridge escrow holds 900 FoT but has issued a 1000-token liability.
7. Repeat N times to accumulate a deficit of `N × 100` tokens.
8. When users bridge back, the EVM bridge calls `safeTransfer(recipient, 1000)` but holds insufficient balance; the last `N × 100 / 1000` users cannot recover their funds. [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

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

**File:** evm/CLAUDE.md (L23-23)
```markdown
**EVM → NEAR (initTransfer)**: User calls `initTransfer` which burns/locks tokens on EVM and emits `InitTransfer` with all transfer details (sender, token, amount, fee, nativeFee, recipient, message). In the Wormhole variant, a Wormhole message is also sent. The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees.
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

**File:** starknet/src/omni_bridge.cairo (L303-307)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```
