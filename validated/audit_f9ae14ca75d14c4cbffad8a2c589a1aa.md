### Title
ETH Delivery Failure to Non-Payable Contract Recipient Permanently Freezes Bridged Funds — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

When a user bridges native ETH (tokenAddress = `address(0)`) from NEAR to EVM and specifies a smart contract address as the EVM recipient, `finTransfer` sends ETH via a low-level `call`. If the recipient contract lacks a payable fallback or intentionally reverts on ETH receipt, the call fails and `finTransfer` reverts with `FailedToSendEther`. Because the NEAR side has already irrevocably locked/burned the user's tokens and provides no cancellation or refund path for failed EVM deliveries, the bridged funds are permanently frozen.

---

### Finding Description

In `OmniBridge.finTransfer`, when `payload.tokenAddress == address(0)`, ETH is delivered to the recipient via:

```solidity
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();
``` [1](#0-0) 

The Solidity revert rolls back `completedTransfers[payload.destinationNonce] = true`, so the nonce is not permanently consumed and the relayer can retry. However, if the recipient contract has no payable fallback (or one that always reverts), every retry will fail identically. The nonce is never finalized, but the NEAR-side tokens are already gone.

On the NEAR side, `init_transfer` locks or burns the user's tokens and emits `InitTransferEvent` before any EVM confirmation: [2](#0-1) 

There is no `cancel_transfer`, `refund_transfer`, or any other mechanism that allows a user or relayer to recover NEAR-side tokens when EVM delivery is permanently impossible. The `pending_transfers` map retains the entry, but no code path converts a perpetually-failing EVM delivery into a NEAR-side refund. [3](#0-2) 

This issue is not documented in `evm/SECURITY.md` as a known or accepted risk. [4](#0-3) 

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

A user who bridges native ETH to any EVM smart contract address that cannot receive ETH (e.g., a multisig wallet, a DAO treasury, a DeFi protocol contract, or any contract without a `receive`/`payable fallback`) will have their NEAR-side tokens permanently locked or burned with no recovery path. The ETH held by the bridge contract is also permanently stranded, since the nonce is never finalized and no admin rescue path exists for this case.

---

### Likelihood Explanation

**Medium.** Bridging ETH to a smart contract address is a common and expected use case (multisigs, protocol treasuries, smart wallets). Many deployed contracts do not implement a payable fallback. A user who does not know this restriction will lose funds with no warning and no recourse. The entry path requires only a standard NEAR `init_transfer` call — no special privileges.

---

### Recommendation

1. **On the EVM side**: Document clearly that `tokenAddress = address(0)` transfers will permanently fail if the recipient is a contract without a payable fallback, and consider emitting a warning event or adding an on-chain check (e.g., checking `recipient.code.length == 0` and reverting early with a descriptive error before the nonce is marked used, so the NEAR side is never committed).

2. **On the NEAR side**: Implement a cancellation or timeout-based refund mechanism for `pending_transfers` entries whose EVM delivery has been permanently failing. This is the structural fix: the NEAR side must be able to recover tokens when the destination chain cannot accept them.

3. **Alternatively**: Require that ETH recipients be EOAs (externally owned accounts) by checking `payload.recipient.code.length == 0` before attempting the transfer, and reject contract recipients for native ETH transfers.

---

### Proof of Concept

1. User on NEAR calls `init_transfer` with `token = address(0)` (native ETH) and `recipient = <EVM_contract_without_payable_fallback>`. NEAR locks/burns the user's tokens and emits `InitTransferEvent`. [5](#0-4) 

2. Relayer calls `OmniBridge.finTransfer` on EVM with a valid MPC signature. The nonce is marked used at line 287, then ETH delivery is attempted at line 319. [6](#0-5) 

3. The recipient contract has no payable fallback. The `call` returns `success = false`. `FailedToSendEther()` is thrown, reverting the entire transaction including the nonce marking.

4. The relayer retries indefinitely — every attempt reverts identically. The NEAR-side tokens remain locked/burned. No refund or cancellation function exists on NEAR. Funds are permanently frozen.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L287-322)
```text
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
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```

**File:** evm/SECURITY.md (L12-21)
```markdown
## Known Issues

Low-severity items acknowledged but not yet addressed:

- **`addCustomToken` can overwrite existing mappings** (H-01): Admin-only function. No existence check — calling with an already-mapped `nearTokenId` silently overwrites `nearToEthToken`. Accepted as operational risk
- **`pause(flags)` replaces all flags** (H-02): `_pause(flags)` does full replacement, not bitwise OR. Calling `pause(PAUSED_INIT_TRANSFER)` when `PAUSED_FIN_TRANSFER` is set will unpause finTransfer. Use `pauseAll()` for emergencies
- **`BridgeToken.initialize` stores metadata redundantly** (L-01): `__ERC20_init(name_, symbol_)` writes to parent storage that is never read (getters are overridden). Minor gas waste on init
- **`require` strings instead of custom errors** (L-02): Several locations use `require` with string messages instead of custom errors (`OmniBridge.sol:150,204,556`, `SelectivePausableUpgradable.sol:100,107`, `ENearProxy.sol:56,76,86`)
- **`OmniBridgeWormhole` has no `__gap`** (L-04): Three storage variables with no gap array. Safe as a leaf contract but would need a gap if inherited from
- **`PayloadType.ClaimNativeFee` defined but unused** (L-05): Enum value 2 is never referenced. Native fees are recovered via `finTransfer` with `tokenAddress=address(0)`
```
