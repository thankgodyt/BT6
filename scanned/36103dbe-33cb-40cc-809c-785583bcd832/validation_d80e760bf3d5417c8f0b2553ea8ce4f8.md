### Title
Permanent Freezing of Bridged Funds via Blacklisted or Reverting Recipient in `finTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::finTransfer()` uses a push-pattern `safeTransfer` to deliver native ERC-20 tokens (e.g., USDT, USDC) directly to `payload.recipient`. If that address is blacklisted by the token contract, the call reverts and the entire `finTransfer` transaction is rolled back. Because the NEAR side has already burned the user's wrapped tokens in `init_transfer_internal` and there is no on-chain cancel or refund path for a stuck pending transfer, the bridged assets are permanently frozen.

---

### Finding Description

**Root cause — EVM push transfer with no fallback:**

In `finTransfer()`, after verifying the MPC signature, the contract unconditionally pushes tokens to `payload.recipient`:

```solidity
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
``` [1](#0-0) 

`SafeERC20.safeTransfer` wraps the low-level call and reverts on failure. For tokens such as USDT and USDC that maintain an address blacklist, any transfer to a blacklisted address reverts. Because the revert unwinds the entire transaction, `completedTransfers[payload.destinationNonce]` is also rolled back, so the nonce is not permanently consumed — but the relayer will fail on every retry with the same payload, since the MPC signature is cryptographically bound to the specific `payload.recipient`. [2](#0-1) 

**Root cause — NEAR side burns tokens with no cancel path:**

On NEAR, `init_transfer_internal` immediately burns (or locks) the user's tokens and records the transfer in `pending_transfers`:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [3](#0-2) 

The only code path that removes a transfer from `pending_transfers` is `claim_fee_callback`, which requires proof of a successful EVM `FinTransfer` event:

```rust
let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
``` [4](#0-3) 

There is no `cancel_transfer`, `withdraw_transfer`, or any other user-callable function that removes a pending transfer and returns tokens to the sender. A grep across all NEAR bridge source files for such patterns returns zero matches. If `finTransfer` on EVM can never succeed, `claim_fee_callback` can never be triggered, and the burned/locked tokens are irrecoverable.

---

### Impact Explanation

**Permanent freezing of bridged funds.** The complete loss path is:

1. User bridges USDT/USDC from EVM to NEAR → native tokens locked in EVM bridge, wrapped tokens minted on NEAR.
2. User initiates a return transfer on NEAR specifying recipient address `R` → wrapped tokens are burned immediately by `burn_tokens_if_needed`.
3. Address `R` is (or becomes) blacklisted by the token issuer.
4. Every relayer attempt to call `finTransfer` on EVM reverts at `safeTransfer(R, amount)`.
5. The MPC signature is bound to `R`; no alternative recipient can be substituted without a new MPC signing round, which the NEAR bridge does not support post-initiation.
6. `claim_fee_callback` is never reachable; `pending_transfers` entry is never removed.
7. Native USDT/USDC remains locked in the EVM bridge forever; wrapped tokens are already burned on NEAR.

This satisfies the allowed critical impact: *permanent freezing of bridged funds across EVM flows*.

---

### Likelihood Explanation

USDT and USDC are the most commonly bridged stablecoins and both implement address-level blacklists enforced at the token contract level. A user may:

- Specify a recipient that is already sanctioned/blacklisted without knowing it.
- Have their recipient address blacklisted by the issuer (e.g., regulatory action) between transfer initiation and EVM finalization — a window that can span minutes to hours depending on relayer latency.

No privileged access, key compromise, or validator collusion is required. The attacker-controlled entry point is the public `ft_on_transfer` / `init_transfer` call on NEAR, which any token holder can invoke.

---

### Recommendation

1. **NEAR — add a timed cancel path:** Expose a `cancel_transfer(transfer_id)` function callable by the original sender after a timeout (e.g., 24 h). It should call `remove_transfer_message`, re-mint burned tokens (or unlock locked tokens), and emit a cancellation event.
2. **EVM — use a pull pattern for failed deliveries:** Wrap the `safeTransfer` in a try/catch (or use a low-level call that checks success without reverting) and, on failure, credit the amount to a claimable balance mapping keyed by `payload.recipient`. This prevents a single blacklisted address from making the nonce permanently unfinalisable.
3. **Starknet — same pattern:** `starknet/src/omni_bridge.cairo::fin_transfer` has the identical push-transfer structure and should receive the same treatment. [5](#0-4) 

---

### Proof of Concept

```
1. Alice holds 1000 USDC on Ethereum.
2. Alice calls OmniBridge.initTransfer(USDC, 1000, ...) on Ethereum.
   → 1000 USDC locked in OmniBridge.
3. Relayer submits proof to NEAR; NEAR mints 1000 wrapped-USDC to Alice.
4. Alice calls ft_transfer_call on NEAR to bridge back to Ethereum,
   specifying recipient = 0xBlacklisted.
   → NEAR burns 1000 wrapped-USDC; transfer stored in pending_transfers.
5. MPC signs TransferMessagePayload{recipient: 0xBlacklisted, amount: 1000, ...}.
6. Relayer calls OmniBridge.finTransfer(sig, payload) on Ethereum.
   → USDC.safeTransfer(0xBlacklisted, 1000) reverts (blacklist check).
   → Entire tx reverts; completedTransfers[nonce] stays false.
7. Relayer retries → same revert every time.
8. No cancel function exists on NEAR → pending_transfers entry never removed.
9. Result: 1000 USDC permanently locked in EVM OmniBridge;
           1000 wrapped-USDC permanently burned on NEAR.
           Alice has lost her funds with no recovery path.
``` [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1829-1864)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
```

**File:** starknet/src/omni_bridge.cairo (L250-263)
```text
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
