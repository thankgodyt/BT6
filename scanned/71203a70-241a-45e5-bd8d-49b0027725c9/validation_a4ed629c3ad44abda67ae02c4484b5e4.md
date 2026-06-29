### Title
Pending Transfers for Tokens Unregistered on the Destination Chain Permanently Freeze User Funds — (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and finalizes a transfer (burning/locking user tokens and storing the entry in `pending_transfers`) without verifying that the transferred token has a registered address on the destination chain. This critical validation is deferred to `sign_transfer`, which panics with `FailedToGetTokenAddress` if the mapping is absent. Because no public cancel or withdrawal path exists for pending transfers, the user's funds are permanently frozen in the bridge.

### Finding Description

The outbound NEAR → foreign-chain transfer flow is two-step:

**Step 1 — `init_transfer` (via `ft_transfer_call`):**

`init_transfer` performs only two checks before committing the transfer: [1](#0-0) 

- recipient chain is not NEAR
- `fee < amount`

It then calls `init_transfer_internal`, which inserts the entry into `pending_transfers`, burns or locks the user's tokens, and returns `U128(0)` to the NEP-141 `ft_transfer_call` mechanism — signalling that no refund should be issued: [2](#0-1) 

At this point the user's tokens are gone (burned for deployed tokens, locked for native tokens) and the transfer is recorded.

**Step 2 — `sign_transfer` (called by a trusted relayer):**

`sign_transfer` is where the deferred validations live: [3](#0-2) 

1. `get_token_address(destination_chain, token_id)` — panics with `FailedToGetTokenAddress` if the token has no registered address on the destination chain.
2. `token_decimals.get(&token_address)` — panics with `TokenDecimalsNotFound` if decimals are absent.
3. `amount_to_transfer > 0` — panics with `InvalidAmountToTransfer` if the amount normalizes to zero (e.g., a dust amount sent to a chain with fewer decimals).

None of these three conditions are checked in `init_transfer` or `init_transfer_internal`.

**No recovery path exists.** The only internal functions that remove a pending transfer are `remove_transfer_message` (called only on a successful MPC signing when fee is zero) and `remove_transfer_message_without_refund` (called only on a storage-balance failure inside `init_transfer_internal`): [4](#0-3) 

There is no public `cancel_transfer`, `withdraw_pending_transfer`, or equivalent function exposed to users or relayers.

### Impact Explanation

A user who initiates a transfer of a token that is registered on some chains but not on the intended destination chain will have their tokens permanently burned or locked in the bridge with no recovery mechanism. The `pending_transfers` entry is irremovable without a contract upgrade. This constitutes a **critical permanent freezing of bridged funds**.

### Likelihood Explanation

The bridge supports many chains (Eth, Arb, Base, Bnb, Pol, Sol, Strk, BTC, Zcash, HyperEvm, Abs, Fogo). A token is typically registered on a subset of these chains. A user who specifies a destination chain for which their token has no binding — either by mistake or because the binding was removed after the transfer was queued — will trigger this condition. The `amount_to_transfer == 0` variant is also reachable for dust amounts sent to chains with fewer decimals. Both paths are reachable by any unprivileged user via the public `ft_transfer_call` entry point.

### Recommendation

Perform all validations that `sign_transfer` relies on **inside `init_transfer`** before tokens are burned or locked:

1. Assert `get_token_address(destination_chain, token_id)` returns `Some(...)`.
2. Assert `token_decimals` contains an entry for that address.
3. Assert `normalize_amount(amount - fee, decimals) > 0`.

If any check fails, return the full `amount` from `ft_on_transfer` so the NEP-141 mechanism refunds the user automatically, mirroring the pattern already used for storage-balance failures in `init_transfer_internal`.

Additionally, consider adding a DAO-accessible `cancel_pending_transfer` function as a safety valve for transfers that become permanently uncompletable due to post-queue state changes (e.g., token binding removal).

### Proof of Concept

1. Token `foo.near` is registered on `ChainKind::Eth` but **not** on `ChainKind::Sol`.
2. User calls `ft_transfer_call` on `foo.near` with `receiver_id = omni-bridge.near` and `msg` encoding an `InitTransferMsg` whose `recipient` is a Solana address.
3. `init_transfer` passes both checks (recipient chain ≠ Near, fee < amount).
4. `init_transfer_internal` inserts the entry into `pending_transfers`, calls `lock_tokens_if_needed` (tokens locked), and returns `U128(0)` — no refund issued.
5. A trusted relayer calls `sign_transfer` for this `transfer_id`.
6. `get_token_address(ChainKind::Sol, foo.near)` returns `None` → `env::panic_str(BridgeError::FailedToGetTokenAddress)`.
7. The transfer remains in `pending_transfers` forever; the user's tokens remain locked with no recovery path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L462-485)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L531-557)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
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

**File:** near/omni-bridge/src/lib.rs (L2194-2224)
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

    fn remove_transfer_message_without_refund(
        &mut self,
        transfer_id: TransferId,
    ) -> TransferMessage {
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        transfer.message
    }
```
