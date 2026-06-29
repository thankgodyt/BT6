### Title
Malicious or Non-Compliant Recipient Contract Permanently Freezes Bridged Funds in `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.finTransfer()` makes external calls to the recipient address when delivering ETH (low-level `.call`) and ERC1155 tokens (`safeTransferFrom`, which triggers `onERC1155Received`). If the recipient is a contract that reverts in either hook, the entire `finTransfer` transaction reverts — including the nonce-marking write at line 287. Because the recipient is cryptographically bound in the MPC-signed payload, no retry with a different recipient is possible, and there is no source-chain refund path. The user's source-chain funds are permanently frozen.

---

### Finding Description

`finTransfer` in `OmniBridge.sol` marks the destination nonce used, verifies the MPC signature, then dispatches tokens to the recipient via one of several branches:

**Branch 1 — ETH delivery (line 319):**
```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
```
If `payload.recipient` is a contract without a `receive()` function, or one whose `receive()` reverts, the call fails and `finTransfer` reverts.

**Branch 2 — ERC1155 delivery (line 324):**
```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this),
    payload.recipient,
    multiToken.tokenId,
    payload.amount,
    ""
);
```
`safeTransferFrom` unconditionally calls `onERC1155Received` on the recipient if it is a contract. If the recipient reverts in that hook, `finTransfer` reverts.

In both cases the Solidity revert unwinds `completedTransfers[payload.destinationNonce] = true` (line 287), so the nonce is never consumed. However, the recipient address is part of the Borsh-encoded payload that the MPC signed; any re-submission with the same valid signature carries the same recipient and fails identically. There is no mechanism on the NEAR side to cancel or refund a transfer whose EVM-side finalization is permanently blocked. [1](#0-0) 

---

### Impact Explanation

When a user initiates a NEAR → EVM transfer, the NEAR bridge burns or locks the user's tokens at initiation time. If the EVM-side `finTransfer` can never succeed (because the recipient contract always reverts), the user's source-chain tokens are permanently frozen: burned on NEAR, undeliverable on EVM, with no recovery path. This satisfies the "permanent freezing of bridged funds" critical impact criterion. [2](#0-1) [3](#0-2) 

---

### Likelihood Explanation

An attacker deploys a contract on EVM that initially implements `onERC1155Received` (or `receive()`) correctly, induces a victim to bridge tokens to that address (e.g., as a payment or NFT settlement), then upgrades or toggles the contract to revert. Because the MPC signature is already issued with the attacker's address as recipient, no corrective re-signing is possible. The attack requires the victim to send funds to an attacker-controlled contract — analogous to the PuttyV2 scenario where the victim fills an order containing attacker-controlled token addresses. Likelihood is medium: it requires social engineering to direct the victim's transfer to the attacker's contract, but no privileged access to the bridge itself. [4](#0-3) 

---

### Recommendation

1. **Pull-payment pattern**: Instead of pushing tokens/ETH directly to the recipient in `finTransfer`, store the claimable amount in a mapping keyed by `(recipient, token, nonce)` and let the recipient pull funds in a separate `claim()` call. This decouples delivery failure from nonce consumption.
2. **Try/catch with fallback escrow**: Wrap the external delivery call in a `try/catch`; on failure, escrow the funds under the recipient's address and emit an event so the recipient can claim later.
3. **Source-chain refund path**: Implement a timeout-based cancellation on the NEAR side that allows the sender to reclaim locked/burned tokens if the destination nonce is not consumed within a configurable window. [2](#0-1) 

---

### Proof of Concept

```
1. Attacker deploys MaliciousRecipient on EVM:
   - Initially: onERC1155Received returns correct selector
   - Has an owner-controlled `block` flag

2. Victim initiates ERC1155 transfer on NEAR:
   ft_on_transfer(token, amount, msg={recipient: MaliciousRecipient, ...})
   → NEAR bridge locks victim's tokens
   → MPC signs payload with MaliciousRecipient as recipient

3. Attacker calls MaliciousRecipient.setBlock(true)
   → onERC1155Received now reverts unconditionally

4. Relayer calls OmniBridge.finTransfer(signature, payload):
   → completedTransfers[nonce] = true  (line 287)
   → signature verified OK             (line 311)
   → IERC1155.safeTransferFrom(bridge, MaliciousRecipient, ...) 
      → calls MaliciousRecipient.onERC1155Received → REVERT
   → entire tx reverts, nonce NOT consumed

5. Any subsequent finTransfer call with the same valid signature
   hits the same revert. No alternative signature exists.

6. Victim's NEAR-side tokens remain permanently locked.
``` [1](#0-0) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-355)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```

**File:** evm/CLAUDE.md (L34-36)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
- **No token release without signature**: Never mint, transfer, or unlock tokens to a recipient without first verifying a valid MPC signature. No admin function, emergency path, or refactor may bypass this — it is the only authorization gate for finTransfer
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
