### Title
Deflationary/Fee-on-Transfer Token Deposits Cause Escrow Mis-Accounting Leading to Bridge Insolvency — (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`)

---

### Summary

`initTransfer` on both the EVM and Starknet bridge contracts calls `transferFrom`/`transfer_from` with the caller-supplied `amount` but never verifies the actual balance received. The `InitTransfer` event is emitted with the inflated input `amount`. NEAR finalizes the cross-chain transfer for that inflated amount, and when the reverse leg (`finTransfer`) executes, the bridge attempts to release more tokens than it holds, causing progressive insolvency.

---

### Finding Description

**EVM — `OmniBridge.sol::initTransfer()`**

For a plain ERC20 token (not a bridge token, not a custom minter), the deposit path is:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied, not verified post-transfer
);
```

Immediately after, the event is emitted with the same unverified `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress, currentOriginNonce,
    amount,         // inflated — actual balance may be amount - fee_taken
    fee, nativeFee, recipient, message
);
```

No balance snapshot is taken before or after the transfer to compute the real delta.

**Starknet — `omni_bridge.cairo::init_transfer()`**

The identical pattern:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
// ...
Event::InitTransfer(InitTransfer { ..., amount, ... })
```

`success == true` only confirms the call did not revert; it does not confirm the received amount equals `amount`.

**Finalization leg — `OmniBridge.sol::finTransfer()`**

When the NEAR-signed payload arrives on EVM to release tokens to the recipient, the bridge unconditionally sends `payload.amount` (derived from the inflated event):

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount   // inflated amount signed by NEAR
);
```

Because the bridge holds `amount - fee_taken` per deposit but is obligated to release `amount` per withdrawal, each round-trip drains the bridge's real balance by `fee_taken`. After enough deposits the bridge cannot satisfy legitimate withdrawals.

---

### Impact Explanation

**Critical — Escrow mis-accounting / permanent loss of bridged funds.**

Every deposit of a fee-on-transfer ERC20 (e.g., USDT with fee enabled, any deflationary token) creates a cross-chain obligation larger than the actual custody. The shortfall accumulates silently. Eventually `safeTransfer` in `finTransfer` reverts because the bridge is insolvent, permanently freezing funds for honest users who deposited standard amounts. Attackers can deliberately accelerate this by repeatedly depositing deflationary tokens.

---

### Likelihood Explanation

**Medium-High.** The bridge does not whitelist tokens — any ERC20 address is accepted by `initTransfer`. USDT's fee switch is a well-known latent risk. Numerous deployed fee-on-transfer tokens exist on mainnet. No special role or permission is required; any unprivileged user calling `initTransfer` with such a token triggers the mis-accounting.

---

### Recommendation

1. **Measure actual received amount** using a balance snapshot:
   ```solidity
   uint256 before = IERC20(tokenAddress).balanceOf(address(this));
   IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
   uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - before;
   require(actualReceived == amount, "fee-on-transfer token");
   // emit event with actualReceived, not amount
   ```
2. Apply the same fix to `starknet/src/omni_bridge.cairo::init_transfer()`.
3. Consider an explicit token allowlist or a flag that rejects known fee-on-transfer and rebasing tokens.

---

### Proof of Concept

1. USDT owner enables the 0.5% transfer fee.
2. Attacker (or any user) calls `OmniBridge.initTransfer(USDT, 1_000_000, 0, 0, "near-recipient", "")`.
3. Bridge receives 995,000 USDT; event emits `amount = 1_000_000`.
4. NEAR relayer reads the event, MPC signs a `finTransfer` payload for 1,000,000 USDT to the NEAR recipient.
5. NEAR releases 1,000,000 USDT-equivalent tokens to the recipient.
6. When the user later bridges back 1,000,000 tokens to EVM, `finTransfer` on EVM calls `safeTransfer(recipient, 1_000_000)` but the bridge only holds 995,000 USDT → revert → funds frozen.
7. Repeated deposits widen the shortfall until the bridge is fully insolvent.

---

**Affected files and lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

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
