### Title
Blacklisted Recipient Permanently Locks Bridged Funds in `finTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::finTransfer` performs a token transfer to `payload.recipient` with no error-handling fallback. For non-bridge tokens such as USDC, the call is `IERC20.safeTransfer`, which reverts if the recipient is blacklisted. Because the MPC signature commits to a fixed recipient address and the NEAR-side tokens are already burned before `finTransfer` is ever called, a blacklisted recipient makes the transfer permanently unfinalizeable, causing irreversible loss of the user's bridged funds.

---

### Finding Description

The NEAR → EVM transfer flow is:

1. User calls `ft_on_transfer` on NEAR → tokens burned/locked, `TransferMessage` stored in `pending_transfers`.
2. Relayer calls `sign_transfer` on NEAR → MPC signs a `TransferMessagePayload` that encodes `payload.recipient` in the hash. On success, the `pending_transfers` entry is removed (when `fee.is_zero()`).
3. Relayer submits the signed payload to `OmniBridge.sol::finTransfer` on EVM.

Inside `finTransfer`, the nonce is marked used first, then the token is dispatched to the recipient:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
// ... signature verification ...
// non-bridge token path:
IERC20(payload.tokenAddress).safeTransfer(            // line 351-354
    payload.recipient,
    payload.amount
);
```

If `payload.recipient` is on the USDC (or any token with a blacklist) denylist, `safeTransfer` reverts. Because Solidity reverts roll back the entire transaction, `completedTransfers[payload.destinationNonce]` is also rolled back — the nonce is not consumed. The relayer can retry, but every attempt will revert for the same reason.

The MPC signature is computed over a Borsh-encoded blob that includes `payload.recipient`:

```solidity
Borsh.encodeAddress(payload.recipient),   // line 298
```

This means the signature is irrevocably bound to the blacklisted address. No alternative recipient can be substituted without invalidating the signature, and there is no on-chain mechanism to re-sign with a different recipient.

On the NEAR side, `sign_transfer_callback` removes the `pending_transfers` entry once the MPC signature is obtained:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
```

There is no "cancel transfer" or "un-burn" path on NEAR. Once the tokens are burned and the pending entry is removed, the only recovery route is a successful `finTransfer` on EVM — which is permanently blocked.

---

### Impact Explanation

A user who bridges a non-bridge token (USDC, USDT, or any ERC-20 with a transfer blacklist) from NEAR to an EVM address that is subsequently blacklisted by the token issuer will suffer **permanent, irrecoverable loss** of the full bridged amount. The funds are burned on NEAR and can never be released on EVM. This satisfies the critical impact criterion: permanent freezing of bridged funds.

The same revert-on-transfer issue also applies to:
- ERC-1155 tokens via `IERC1155.safeTransferFrom` (line 324-330) if the recipient does not implement `onERC1155Received`.
- Native ETH (line 319-322) if the recipient is a contract that reverts on `receive`.

---

### Likelihood Explanation

USDC and USDT both maintain on-chain blacklists enforced at the token level. OFAC sanctions and exchange-level compliance actions regularly add addresses to these lists. A user could initiate a bridge transfer to an address that is clean at initiation time but blacklisted before the relayer submits `finTransfer` (e.g., during the MPC signing latency window). This is a realistic, non-negligible scenario for a bridge that explicitly supports USDC and similar tokens.

---

### Recommendation

Adopt a **pull-over-push** pattern for the token delivery in `finTransfer`. Instead of transferring directly to `payload.recipient`, record the claimable amount in a mapping and let the recipient pull it:

```solidity
// Replace direct transfer with:
pendingWithdrawals[payload.recipient][payload.tokenAddress] += payload.amount;
```

Provide a separate `claimTokens(address tokenAddress)` function that the recipient calls to pull their funds. This decouples the finalization of the bridge transfer (nonce consumption, event emission) from the token delivery, so a blacklisted recipient cannot block the protocol-level state transition.

Alternatively, wrap the `safeTransfer` in a try/catch and, on failure, credit the amount to a `claimable[recipient][token]` mapping — analogous to the `claims[token]` pattern recommended in the reference report.

---

### Proof of Concept

1. Alice holds USDC on NEAR (bridged from Ethereum). She calls `ft_on_transfer` to bridge 10,000 USDC back to her Ethereum address `0xAlice`. NEAR burns her USDC and stores the `TransferMessage`.
2. The relayer calls `sign_transfer`; MPC produces a signature over the payload `{recipient: 0xAlice, token: USDC, amount: 10000, ...}`. The `pending_transfers` entry is removed.
3. Before the relayer submits `finTransfer`, USDC's issuer blacklists `0xAlice` (e.g., due to a sanctions designation).
4. The relayer calls `OmniBridge.finTransfer(sig, payload)`. Execution reaches line 351: `IERC20(USDC).safeTransfer(0xAlice, 10000)`. The USDC contract reverts because `0xAlice` is blacklisted.
5. The entire transaction reverts. `completedTransfers[nonce]` is rolled back.
6. Every subsequent retry by any relayer produces the same revert. The signature cannot be reused with a different recipient. There is no NEAR-side recovery path.
7. Alice's 10,000 USDC are permanently destroyed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L295-298)
```text
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L491-500)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```
