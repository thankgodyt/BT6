### Title
Missing Same-Chain Validation in `process_fin_transfer_to_other_chain` Allows Locked-Balance Manipulation and Permanent Token Freezing — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR Omni Bridge does not validate that the origin chain and destination chain differ when processing inbound proofs that route to a non-NEAR recipient. An unprivileged user can call `initTransfer` on an EVM chain with a recipient address on the **same** EVM chain. The NEAR bridge processes this as a legitimate cross-chain transfer, incorrectly reducing the locked-token balance for that chain. This permanently under-counts the tokens that are actually circulating on the EVM side, causing subsequent legitimate return transfers to fail with `InsufficientLockedTokens`, permanently freezing bridged funds.

---

### Finding Description

**EVM entry point — no recipient-chain validation:**

`OmniBridge.sol::initTransfer` accepts any string as `recipient` and emits it verbatim in the `InitTransfer` event. There is no check that the recipient chain differs from the source chain. [1](#0-0) 

A user on Ethereum can call:
```solidity
initTransfer(tokenAddress, 500, 1, 0, "eth:0xAttacker", "")
```
This burns 500 bridge tokens on Ethereum and emits an `InitTransfer` event with an Ethereum recipient.

---

**NEAR routing — no origin == destination guard:**

`fin_transfer_callback` verifies the proof and dispatches to `process_fin_transfer_to_other_chain` whenever the recipient is not a NEAR address. It does **not** check whether `get_origin_chain() == get_destination_chain()`. [2](#0-1) 

Inside `process_fin_transfer_to_other_chain`, the locked-token accounting unconditionally unlocks from the origin chain and locks only the fee amount to the destination chain: [3](#0-2) 

---

**Lock/unlock semantics for bridge tokens:**

`unlock_tokens_if_needed` skips the operation only when `get_token_origin_chain(token_id) == chain_kind`. For a bridge token whose origin is NEAR (deployed on EVM), the origin chain is `ChainKind::Near`, so `unlock_tokens_if_needed(Eth, token, amount)` **does** execute and reduces `locked[Eth][token]` by `amount`. [4](#0-3) 

---

**Concrete accounting corruption:**

| Step | Action | `locked[Eth][T]` | Eth-side supply |
|---|---|---|---|
| Initial | 1000 tokens on Eth | 1000 | 1000 |
| Attacker `initTransfer` Eth→Eth, amount=500, fee=1 | 500 burned on Eth | 1000 | 500 |
| NEAR `fin_transfer_callback` | `unlock(Eth, 500)`, `lock(Eth, 1)` | **501** | 500 |
| `finTransfer` on Eth | 499 minted to attacker | 501 | **999** |

After the attack: `locked[Eth][T] = 501` but actual Eth supply = 999. The discrepancy is 498 tokens.

When any user later tries to return 502+ tokens from Eth to NEAR, `unlock_tokens_if_needed(Eth, T, amount)` panics with `InsufficientLockedTokens`: [5](#0-4) 

Those tokens are permanently frozen on Ethereum.

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.** An attacker spends 1 token (the fee) to permanently freeze 499 tokens belonging to other users. The attack is repeatable: each iteration costs 1 token and freezes ~499 tokens. Affected tokens are bridge tokens whose canonical origin is NEAR (deployed on EVM via `deployToken`). They can never be returned to NEAR because the locked-balance invariant is broken.

---

### Likelihood Explanation

**High.** The entry path requires only a standard EVM `initTransfer` call with a same-chain recipient string (e.g., `"eth:0x..."`). No special role, no admin access, no leaked key. Any token holder on any supported EVM chain can trigger this. A relayer (which can also be the attacker) submits the proof to NEAR to complete the accounting corruption.

---

### Recommendation

Add a guard in `fin_transfer_callback` (or at the top of `process_fin_transfer_to_other_chain`) that rejects transfers where the origin chain equals the destination chain:

```rust
require!(
    transfer_message.get_origin_chain() != transfer_message.get_destination_chain(),
    BridgeError::InvalidRecipientChain.as_ref()
);
```

This mirrors the existing guard for NEAR→NEAR transfers in `init_transfer`: [6](#0-5) 

The same guard should be applied symmetrically in `process_fin_transfer_to_other_chain` to cover the inbound proof path. [7](#0-6) 

---

### Proof of Concept

1. Deploy bridge token `T` (origin = NEAR) on Ethereum. Assume `locked[Eth][T] = 1000`.
2. Attacker calls on Ethereum:
   ```solidity
   OmniBridge.initTransfer(T_address, 500, 1, 0, "eth:0xAttacker", "")
   ```
   500 tokens burned. `InitTransfer` event emitted with `recipient = "eth:0xAttacker"`.
3. Relayer (or attacker) calls `fin_transfer` on NEAR with the Ethereum proof.
4. `fin_transfer_callback` → `process_fin_transfer_to_other_chain`:
   - `unlock_tokens_if_needed(Eth, T, 500)` → `locked[Eth][T] = 500`
   - `lock_tokens_if_needed(Eth, T, 1)` → `locked[Eth][T] = 501`
   - Transfer message stored.
5. `sign_transfer` called; MPC signs payload for Eth destination.
6. Attacker calls `finTransfer` on Ethereum; 499 tokens minted to attacker.
7. **State**: `locked[Eth][T] = 501`, actual Eth supply = 999.
8. Victim holding 502 tokens tries to return them to NEAR via `fin_transfer`. NEAR panics: `ERR_INSUFFICIENT_LOCKED_TOKENS`. Victim's 502 tokens are permanently frozen on Ethereum.

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L734-745)
```rust
        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
```

**File:** near/omni-bridge/src/lib.rs (L1980-2006)
```rust
    fn process_fin_transfer_to_other_chain(
        &mut self,
        predecessor_account_id: AccountId,
        transfer_message: TransferMessage,
    ) {
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());
        let token = self.get_token_id(&transfer_message.token);

        if transfer_message.recipient.is_utxo_chain() {
            let btc_account_id =
                self.get_utxo_chain_token(transfer_message.get_destination_chain());
            require!(
                token == btc_account_id,
                BridgeError::NativeTokenRequiredForChain.as_ref()
            );
        }

        self.unlock_tokens_if_needed(
            transfer_message.get_origin_chain(),
            &token,
            transfer_message.amount.0,
        );
        self.lock_tokens_if_needed(
            transfer_message.get_destination_chain(),
            &token,
            transfer_message.fee.fee.into(),
        );
```

**File:** near/omni-bridge/src/token_lock.rs (L78-84)
```rust
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );
```

**File:** near/omni-bridge/src/token_lock.rs (L109-120)
```rust
    pub(crate) fn unlock_tokens_if_needed(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        if self.get_token_origin_chain(token_id) == chain_kind || amount == 0 {
            return LockAction::Unchanged;
        }

        self.unlock_tokens(chain_kind, token_id, amount)
    }
```
