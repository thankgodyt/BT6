### Title
Blacklisted ERC-20 Recipient Permanently Freezes Bridged Funds in `finTransfer` - (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer` (EVM) and `omni_bridge.fin_transfer` (Starknet) unconditionally push tokens to the MPC-signed `payload.recipient`. If that address is blacklisted by the token (e.g., USDC/USDT) between the time the transfer is initiated on NEAR and the time `finTransfer` is called on the destination chain, the call reverts on every attempt. Because the recipient is cryptographically bound inside the MPC signature, no alternative delivery path exists, and the corresponding NEAR-side locked/burned tokens are permanently frozen.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` follows this sequence:

1. Mark nonce used: `completedTransfers[payload.destinationNonce] = true` (line 287).
2. Verify MPC signature over a payload that includes `payload.recipient` (lines 289–313).
3. Deliver tokens to `payload.recipient` (lines 315–355).

For native ERC-20 tokens (the `else` branch), delivery is:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
```

`SafeERC20.safeTransfer` propagates any revert from the token contract. USDC and USDT both implement a blocklist that causes `transfer` to revert when either party is blocked. If `payload.recipient` is blocked, the entire `finTransfer` transaction reverts, rolling back the `completedTransfers` write as well. The nonce is therefore never consumed, but the call will revert identically on every future retry because the recipient is immutably encoded in the already-issued MPC signature.

The Starknet bridge has the identical structure in `omni_bridge.cairo`:

```cairo
_set_transfer_finalised(ref self, payload.destination_nonce); // rolled back on panic
// ...
let success = IERC20Dispatcher { contract_address: payload.token_address }
    .transfer(payload.recipient, payload.amount.into());
assert(success, 'ERR_TRANSFER_FAILED');
```

On the NEAR side, the tokens were already locked (for native tokens) or burned (for bridge-deployed tokens) when `init_transfer` / `ft_transfer_call` was processed. There is no public admin function to cancel a `pending_transfers` entry and return the tokens to the sender.

---

### Impact Explanation

**Permanent freezing of bridged funds.** The user's tokens are locked or burned on NEAR at `init_transfer` time. If the EVM/Starknet recipient is subsequently blacklisted by the token issuer, `finTransfer` will revert on every call. Because the recipient address is part of the MPC-signed payload, no relayer can substitute a different recipient without an entirely new MPC signing round (which the protocol does not support for already-pending transfers). The funds are irrecoverably stuck.

This matches the allowed impact: *"permanent freezing of bridged funds across NEAR, EVM … or Starknet … flows."*

---

### Likelihood Explanation

USDC and USDT are among the most-bridged assets and both maintain active blocklists. A user whose EVM address is blocked by Circle or Tether after initiating a NEAR → EVM transfer (e.g., due to a compliance action, exchange hack attribution, or sanctions designation) will trigger this condition without any attacker involvement. The window between `init_transfer` on NEAR and `finTransfer` on EVM can be minutes to hours, which is sufficient for a blocklist update to occur.

---

### Recommendation

Wrap the token delivery in a try/catch (EVM) or equivalent error-handling pattern, and on failure store the amount in a per-recipient claimable mapping rather than reverting the entire transaction. This allows the nonce to be consumed (preventing replay) while giving the recipient (or an admin-designated alternative address) a separate path to recover the funds.

```solidity
// Example mitigation sketch
try IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount) {
    // success
} catch {
    claimable[payload.tokenAddress][payload.recipient] += payload.amount;
    emit TransferDeliveryFailed(payload.destinationNonce, payload.recipient);
}
```

A corresponding `claim` function would let the recipient (or, after a timeout, an admin-designated address) withdraw the escrowed amount.

---

### Proof of Concept

1. Alice holds 10,000 USDC on NEAR (as a bridged token).
2. Alice calls `ft_transfer_call` on NEAR, initiating a transfer to her EVM address `0xAlice`. NEAR burns/locks the tokens and records the transfer in `pending_transfers`.
3. Before the relayer calls `finTransfer` on Ethereum, Circle adds `0xAlice` to the USDC blocklist.
4. The relayer calls `OmniBridge.finTransfer(sig, payload)` where `payload.recipient = 0xAlice` and `payload.tokenAddress = USDC`.
5. `IERC20(USDC).safeTransfer(0xAlice, 10000e6)` reverts (USDC blocklist check fails).
6. The entire transaction reverts; `completedTransfers[nonce]` is rolled back to `false`.
7. Every subsequent `finTransfer` attempt with the same MPC-signed payload reverts identically.
8. Alice's 10,000 USDC equivalent is permanently frozen: burned/locked on NEAR, undeliverable on Ethereum.

**Affected files:** [1](#0-0) [2](#0-1)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-355)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** starknet/src/omni_bridge.cairo (L247-263)
```text
            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```
