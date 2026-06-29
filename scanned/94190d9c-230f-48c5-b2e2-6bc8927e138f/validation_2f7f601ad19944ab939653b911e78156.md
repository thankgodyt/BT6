### Title
Dust Transfer Permanently Locks/Burns User Tokens When Normalized Amount Rounds to Zero - (`near/omni-bridge/src/lib.rs`)

### Summary

`init_transfer` accepts and finalizes (burns or locks) user tokens without verifying that the transfer amount, after decimal normalization, is non-zero. When `sign_transfer` is later called, it rejects the transfer because the normalized amount is zero. Since there is no public cancel/refund path for pending transfers, the user's tokens are permanently lost.

### Finding Description

The NEAR bridge supports tokens whose on-chain decimal precision differs between the origin chain (NEAR) and the destination chain (e.g., Ethereum). The `normalize_amount` function converts a NEAR-denominated amount to the destination chain's denomination using floor division: [1](#0-0) 

When `origin_decimals > decimals` (e.g., 24 on NEAR vs. 18 on Ethereum, `diff = 6`), any amount strictly less than `10^6` normalizes to zero.

`init_transfer` only validates that `fee < amount`: [2](#0-1) 

It does **not** check that `normalize_amount(amount - fee) > 0`. After this check passes, `init_transfer_internal` immediately burns (for deployed tokens) or locks (for native tokens) the full amount and stores the pending transfer: [3](#0-2) 

Later, when a relayer calls `sign_transfer`, the normalized amount is computed and a guard rejects it: [4](#0-3) 

`sign_transfer` panics with `BridgeError::InvalidAmountToTransfer`, so the MPC signing request is never made. The transfer record remains in `pending_transfers` indefinitely, and there is no public function to cancel a pending transfer and recover the locked/burned tokens. `remove_transfer_message` is an internal helper called only from `sign_transfer_callback` (when fee is zero, after a successful MPC signature) and `claim_fee_callback`: [5](#0-4) 

Neither path is reachable when `sign_transfer` itself panics before issuing the MPC call.

### Impact Explanation

**Critical.** Any user who initiates a NEAR→foreign transfer with an amount below the decimal normalization threshold for that token loses their funds permanently. The tokens are burned or locked on NEAR, the transfer can never be signed, and no recovery mechanism exists. This is a direct, irreversible loss of bridged funds triggered by a normal, unprivileged user action (`ft_transfer_call`).

### Likelihood Explanation

**Medium.** The condition requires a token registered with `origin_decimals > decimals` (e.g., a token with 24 NEAR decimals normalized to 18 EVM decimals). Such tokens are realistic (NEAR-native tokens bridged to Ethereum commonly undergo this normalization). A user sending a "dust" amount — either accidentally or as a griefing attack against themselves or others — triggers the loss. No special privileges are required.

### Recommendation

Add a normalization check inside `init_transfer` (or `init_transfer_internal`) before burning/locking tokens. Specifically, after computing the fee-adjusted amount, verify that `normalize_amount(amount - fee, decimals) > 0` and revert (return the full amount as a NEP-141 refund) if it is zero. The token address and decimals are already available at `sign_transfer` time; they should be looked up at `init_transfer` time as well, or the check should be added as a pre-condition gating `init_transfer_internal`.

Additionally, consider adding a public `cancel_transfer` function (callable by the transfer owner) that removes the pending transfer record and unlocks/re-mints the tokens, as a defense-in-depth measure for any future stuck-transfer scenarios.

### Proof of Concept

1. Register a token with `origin_decimals = 24`, `decimals = 18` (diff = 6, normalization factor = 10^6).
2. User calls `ft_transfer_call` on the NEAR token contract with `amount = 500_000` (< 10^6) and `fee = 0`, routing to the bridge's `ft_on_transfer`.
3. `init_transfer` passes the `fee < amount` check (0 < 500_000). `init_transfer_internal` burns/locks 500_000 tokens and stores the pending transfer. Returns `U128(0)` — tokens consumed.
4. Relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 })` = `500_000 / 1_000_000` = `0`.
6. `require!(0 > 0, ...)` panics. The MPC call is never made.
7. The 500_000 tokens are permanently burned/locked. No public function can recover them. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
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

**File:** near/omni-bridge/src/lib.rs (L1850-1864)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
