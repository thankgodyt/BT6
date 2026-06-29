### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer()` calls `safeTransferFrom(msg.sender, address(this), amount)` for non-bridge ERC-20 tokens, then unconditionally emits `InitTransfer(..., amount, ...)` using the caller-supplied `amount` parameter — not the actual balance delta received. For fee-on-transfer tokens, the bridge receives fewer tokens than `amount`, but the emitted event instructs the NEAR side to credit the full `amount`. This permanently undercollateralizes the EVM escrow.

---

### Finding Description

In `OmniBridge.initTransfer()`, the non-bridge-token branch performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // ← caller-supplied parameter
);
```

followed immediately by:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // ← same caller-supplied parameter, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
```

`SafeERC20.safeTransferFrom` only checks that `transferFrom` returns `true`; it does not verify the actual balance increase. For a fee-on-transfer ERC-20, the bridge receives `amount − fee_deducted` tokens while the event records `amount`.

The NEAR bridge parses this `InitTransfer` event log in `fin_transfer_callback` and uses `init_transfer.amount` directly to determine how many tokens to mint or release to the recipient on NEAR. No independent balance measurement is performed on either side.

The identical pattern exists in `starknet/src/omni_bridge.cairo` `init_transfer()`, which calls `transfer_from(caller, get_contract_address(), amount.into())` and then emits `InitTransfer { ..., amount, ... }` without measuring the actual received balance.

---

### Impact Explanation

Every `initTransfer` call with a fee-on-transfer token creates a shortfall: the EVM bridge holds `amount − fee_deducted` tokens but the NEAR side mints/releases `amount` tokens to the recipient. The deficit accumulates with each such transfer. Eventually the EVM escrow cannot cover all outstanding NEAR-side claims, causing the last users to withdraw to lose funds permanently. This is a direct, permanent loss of bridged funds — the bridge becomes insolvent for that token.

---

### Likelihood Explanation

The `initTransfer` function is permissionless: any user can call it with any ERC-20 token address. Fee-on-transfer tokens (e.g., tokens with built-in tax mechanisms, reflection tokens, or tokens with configurable transfer fees) are a well-known and deployed token class. No admin action is required to trigger this path. A single user bridging such a token is sufficient to begin the undercollateralization.

---

### Recommendation

Measure the actual balance change around the `safeTransferFrom` call and use the delta — not the `amount` parameter — in the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived (cast to uint128) in the event and downstream accounting
```

Apply the same fix to `starknet/src/omni_bridge.cairo` `init_transfer()`. Alternatively, document that fee-on-transfer tokens are explicitly unsupported and add a registry or allowlist of approved tokens.

---

### Proof of Concept

1. Deploy or use any ERC-20 token that deducts a 1% fee on every `transferFrom` (e.g., a reflection token).
2. Approve `OmniBridge` for `10_000` tokens.
3. Call `OmniBridge.initTransfer(tokenAddress, 10_000, 0, 0, "alice.near", "")`.
4. `safeTransferFrom` executes; bridge receives `9_900` tokens (1% fee deducted by the token).
5. `InitTransfer` event is emitted with `amount = 10_000`.
6. Relayer submits the event proof to NEAR `fin_transfer`.
7. NEAR bridge calls `fin_transfer_callback`, reads `init_transfer.amount = 10_000`, and mints/releases `10_000` tokens to `alice.near`.
8. EVM bridge escrow is short by `100` tokens per transfer. After enough transfers the escrow is drained and subsequent withdrawals from NEAR → EVM fail.

**Root cause lines:** [1](#0-0) [2](#0-1) 

**NEAR side consuming the event amount without independent verification:** [3](#0-2) 

**Starknet analog:** [4](#0-3)

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

**File:** near/omni-bridge/src/lib.rs (L722-732)
```rust
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
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
