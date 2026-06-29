### Title
Unbounded ETH Transfer to Attacker-Controlled Recipient Enables Permanent Freezing of Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`finTransfer` in `OmniBridge.sol` delivers native ETH to `payload.recipient` via an uncapped low-level call. A recipient that is (or becomes) a contract whose `receive()` always reverts will cause every relay attempt to revert. Because the MPC signature binds the recipient address, the relayer cannot substitute a different address. The source-chain tokens (burned or locked during `initTransfer`) are permanently unrecoverable, and no on-chain cancellation or admin-rescue path exists.

---

### Finding Description

`finTransfer` processes the ETH-native path as follows:

```solidity
// OmniBridge.sol line 287
completedTransfers[payload.destinationNonce] = true;

// ... signature verification ...

// line 317-322
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}

// line 357
finTransferExtension(payload);   // Wormhole publish / fee notification
``` [1](#0-0) [2](#0-1) [3](#0-2) 

The call at line 319 forwards **all remaining gas** to `payload.recipient` with no `{gas: N}` cap. If the recipient's `receive()` reverts (or consumes all gas and reverts), the entire transaction reverts — including the `completedTransfers` write at line 287. The nonce is therefore never permanently consumed, so the relayer can retry, but every retry will fail identically.

The recipient address is covered by the MPC-derived ECDSA signature:

```solidity
Borsh.encodeAddress(payload.recipient),   // line 298
...
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
``` [4](#0-3) 

No relayer or admin can substitute a different recipient. There is no `cancelTransfer`, emergency-withdrawal, or admin-rescue function anywhere in `OmniBridge.sol` or `OmniBridgeWormhole.sol`. [5](#0-4) 

The same unbounded-callback pattern exists for the ERC-1155 path, where `safeTransferFrom` triggers `onERC1155Received` on the recipient with no gas cap:

```solidity
IERC1155(multiToken.tokenAddress).safeTransferFrom(
    address(this), payload.recipient, multiToken.tokenId, payload.amount, ""
);
``` [6](#0-5) 

---

### Impact Explanation

When a user bridges ETH (or an ERC-1155 token) from NEAR to Ethereum:

1. On NEAR, `init_transfer_internal` burns or locks the source-chain tokens — this is irreversible once the NEAR transaction is final.
2. On Ethereum, `finTransfer` must succeed to release the locked ETH and publish the Wormhole `FinTransfer` message that lets the NEAR side mark the transfer complete and pay the relayer fee.

If `finTransfer` can never succeed, the source-chain tokens are permanently burned/locked with no recovery path. This is **permanent freezing of bridged funds**. [7](#0-6) 

---

### Likelihood Explanation

The recipient address is chosen by the **sender** during `initTransfer`. Two realistic paths exist:

1. **Sender specifies a contract address** whose `receive()` always reverts (e.g., a multisig or proxy that does not accept plain ETH). This requires no adversarial action by the recipient — the sender may simply make a mistake.

2. **EIP-7702 upgrade**: The recipient is initially an EOA. After observing the `InitTransfer` event on NEAR (public), the recipient upgrades their EOA to a malicious delegate contract before the relayer calls `finTransfer`. The relayer's transaction window is not instantaneous, giving the recipient time to act without strict mempool front-running.

In both cases the attacker-controlled entry path is `finTransfer` called by any relayer with a valid MPC signature — a fully public, permissionless function.

---

### Recommendation

- **Short term:** Cap the gas forwarded to the recipient: `payload.recipient.call{value: payload.amount, gas: 2300}("")`. This prevents complex execution in the recipient's `receive()`.
- **Medium term:** Add an admin-controlled `rescueTransfer(uint64 destinationNonce, address alternativeRecipient)` that can redirect a permanently-stuck transfer to a safe address, callable only after a timeout.
- **Long term:** Consider a pull-payment pattern: credit the recipient's balance in a mapping and let them withdraw, removing the external call from the critical path entirely.

---

### Proof of Concept

1. Alice initiates a transfer on NEAR: burns 1 wETH, specifies Bob's Ethereum address as recipient. NEAR MPC nodes sign the `TransferMessagePayload` binding `recipient = Bob`.

2. Bob deploys (or EIP-7702-delegates) a contract at his address with:
   ```solidity
   receive() external payable {
       revert("no ETH");
   }
   ```

3. Relayer calls `finTransfer` with the valid MPC signature and `payload.recipient = Bob`.

4. Execution reaches line 319: `Bob.call{value: 1 ether}("")` → reverts.

5. `FailedToSendEther` is thrown; the entire transaction reverts, including the `completedTransfers[nonce] = true` write.

6. Relayer retries — same result every time.

7. Alice's 1 wETH on NEAR is permanently burned. The 1 ETH remains locked in the bridge contract forever. No admin function can recover it. [2](#0-1) [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-287)
```text
        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L298-312)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L357-357)
```text
        finTransferExtension(payload);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-598)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }

    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }

    function setNearBridgeDerivedAddress(
        address nearBridgeDerivedAddress_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearBridgeDerivedAddress = nearBridgeDerivedAddress_;
    }

    receive() external payable {}

    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }

    function _normalizeDecimals(uint8 decimals) internal pure returns (uint8) {
        uint8 maxAllowedDecimals = 18;
        if (decimals > maxAllowedDecimals) {
            return maxAllowedDecimals;
        }
        return decimals;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    uint256[49] private __gap;
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```
