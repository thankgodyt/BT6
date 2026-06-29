### Title
Fee-on-Transfer Token Escrow Over-Accounting in `initTransfer()` Enables Vault Drain — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.sol`'s `initTransfer()` locks native ERC-20 tokens via `safeTransferFrom` but emits the caller-supplied `amount` in the `InitTransfer` event without measuring the actual balance received. For fee-on-transfer tokens, the vault holds `amount − transfer_fee` while the event (and therefore the NEAR side) records `amount`. NEAR mints the full `amount` of bridged tokens. When those bridged tokens are redeemed back to EVM, `finTransfer()` attempts to release the full `amount` from the vault, which is short by the accumulated transfer fees — draining funds from other depositors.

### Finding Description

In `initTransfer()`, the native-token lock path is:

```solidity
// OmniBridge.sol lines 407-411
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied; actual receipt may be less
);
```

Immediately after, the event is emitted with the same caller-supplied `amount`:

```solidity
// OmniBridge.sol lines 427-436
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // NOT the actual received balance
    fee,
    nativeFee,
    recipient,
    message
);
```

The NEAR-side prover parses this event and uses `event.data.amount` verbatim as the canonical transfer amount:

```rust
// near/omni-types/src/evm/events.rs lines 126
amount: near_sdk::json_types::U128(event.data.amount),
```

This `amount` is then used to mint bridged tokens on NEAR. The project's own security invariant (documented in `evm/CLAUDE.md` line 36) states:

> *"The NEAR side will treat any emitted event as proof that tokens are held."*

For a fee-on-transfer token, this invariant is broken: the event claims `amount` is held, but the vault only holds `amount − fee`.

### Impact Explanation

**Critical — escrow mis-accounting leading to vault drain / theft of bridged funds.**

Round-trip attack:
1. User calls `initTransfer(feeToken, 1000, ...)`. Vault receives 990 (1% fee). Event records 1000.
2. NEAR mints 1000 bridged tokens to the user.
3. User bridges 1000 bridged tokens back to EVM. NEAR burns 1000 bridged tokens; `finTransfer()` calls `safeTransfer(recipient, 1000)`.
4. Vault holds only 990 → either the call reverts (DoS for the last redeemer) or, if other users have deposited in the interim, 10 tokens are silently taken from their deposits.

Each round trip extracts `transfer_fee` from the collective vault. With enough iterations or a high fee rate, the vault is fully drained. The over-minted bridged tokens on NEAR represent unbacked supply — a classic escrow mis-accounting / unauthorized minting scenario.

### Likelihood Explanation

**Medium-High.** The bridge is designed to support whitelisted tokens. USDT on Ethereum has a fee-on-transfer mechanism that is currently set to zero but can be activated by the USDT issuer at any time without any on-chain action required from the bridge. Any whitelisted token that activates or already has a non-zero transfer fee immediately triggers this vulnerability. No special privilege is required from the attacker — a standard `initTransfer` call suffices.

### Recommendation

Measure the actual received balance using a before/after balance check and use that as the canonical amount in the event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived (cast to uint128) in the event and downstream logic
```

Alternatively, enforce that whitelisted tokens cannot have a non-zero transfer fee, and add an on-chain check or off-chain monitoring to detect fee activation.

### Proof of Concept

1. Assume `feeToken` is a whitelisted ERC-20 with a 1% transfer fee (e.g., USDT with fee activated).
2. Attacker calls `OmniBridge.initTransfer(feeToken, 1000e6, 0, 0, "near:attacker.near", "")`.
3. `safeTransferFrom` transfers 1000e6 from attacker; vault receives 990e6. [1](#0-0) 
4. `InitTransfer` event emits `amount = 1000e6`. [2](#0-1) 
5. NEAR prover reads `event.data.amount = 1000e6` and mints 1000e6 bridged tokens to `attacker.near`. [3](#0-2) 
6. Attacker calls `fin_transfer` on NEAR to bridge 1000e6 back to EVM. NEAR burns 1000e6 bridged tokens.
7. EVM `finTransfer` calls `safeTransfer(attacker_evm, 1000e6)` but vault only holds 990e6. [4](#0-3) 
8. If other users have deposited in the vault, the attacker receives 1000e6 (10e6 stolen from others). If not, the call reverts — but the 1000e6 of unbacked bridged tokens remain in circulation on NEAR, representing permanent over-minting.

The violated invariant is explicitly documented: [5](#0-4)

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

**File:** near/omni-types/src/evm/events.rs (L115-135)
```rust
impl TryFromLog<Log<InitTransfer>> for InitTransferMessage {
    type Error = String;

    fn try_from_log(chain_kind: ChainKind, event: Log<InitTransfer>) -> Result<Self, Self::Error> {
        Ok(Self {
            emitter_address: OmniAddress::new_from_evm_address(
                chain_kind,
                H160(event.address.into()),
            )?,
            origin_nonce: event.data.originNonce,
            token: OmniAddress::new_from_evm_address(chain_kind, H160(event.tokenAddress.into()))?,
            amount: near_sdk::json_types::U128(event.data.amount),
            recipient: event.data.recipient.parse().map_err(stringify)?,
            fee: Fee {
                fee: near_sdk::json_types::U128(event.data.fee),
                native_fee: near_sdk::json_types::U128(event.data.nativeTokenFee),
            },
            sender: OmniAddress::new_from_evm_address(chain_kind, H160(event.data.sender.into()))?,
            msg: event.data.message,
        })
    }
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
