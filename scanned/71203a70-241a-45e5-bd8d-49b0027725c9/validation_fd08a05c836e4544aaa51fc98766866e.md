### Title
Unregistered Tokens Sent to NEAR `omni-bridge` via `ft_on_transfer` Become Permanently Frozen - (File: near/omni-bridge/src/lib.rs)

---

### Summary

The NEAR `omni-bridge` contract's `ft_on_transfer` entry point accepts any NEP-141 token transfer and routes it to `init_transfer` without first verifying that the transferred token is registered in the bridge's token registry (`token_id_to_address`). The bridge consumes the tokens (returns `U128(0)`, keeping them in its account), stores a pending transfer, and only fails later when `sign_transfer` is called — at which point the tokens are already irrecoverably held by the bridge with no cancel or rescue path.

---

### Finding Description

`ft_on_transfer` is the public NEP-141 receiver entry point. Any user can trigger it by calling `ft_transfer_call` on any NEP-141 token contract, naming the bridge as receiver. The bridge dispatches to `init_transfer` for the `InitTransfer` message variant: [1](#0-0) 

Inside `init_transfer`, the only validation performed is that the recipient chain is not NEAR and that `fee < amount`. There is **no check** that `token_id` exists in `token_id_to_address` or `token_address_to_id`: [2](#0-1) 

The function proceeds to store the transfer message and returns `U128(0)` (consuming all tokens). The tokens are now held by the bridge contract.

When a relayer later calls `sign_transfer`, the contract attempts to resolve the token address: [3](#0-2) 

This panics with `ERR_FAILED_TO_GET_TOKEN_ADDRESS` for any unregistered token, permanently blocking the transfer. There is no `cancel_transfer`, `withdraw_token`, or any other built-in rescue function in the contract. The only documented public functions are `ft_on_transfer`, `fin_transfer`, `sign_transfer`, `deploy_token`, `log_metadata`, `update_transfer_fee`, and `claim_fee`: [4](#0-3) 

The contract is upgradeable, but upgradeability is an admin-only escape hatch, not a user-accessible recovery path.

---

### Impact Explanation

Any NEP-141 token sent to the bridge via `ft_transfer_call` with an `InitTransfer` message, where the token is not registered in the bridge's registry, is permanently frozen inside the bridge contract. The user loses their tokens with no recourse. This matches the allowed impact scope: **permanent freezing of bridged funds on NEAR**.

---

### Likelihood Explanation

This is reachable by any unprivileged user. Realistic triggering scenarios include:

- A user attempts to bridge a token that has not yet been registered (e.g., they call `log_metadata` but `deploy_token`/`bind_token` has not yet been finalized on the destination chain).
- A user sends the wrong token to the bridge (e.g., sends `token-a.near` to a bridge that only has `token-b.near` registered).
- A token is deregistered or migrated after a transfer is initiated.

The `ft_transfer_call` → `ft_on_transfer` path is the standard, documented way to initiate a bridge transfer, making accidental misuse highly plausible.

---

### Recommendation

Add a registration check at the start of `init_transfer`. If the token is not found in `token_id_to_address` for the destination chain, return the full `amount` from `ft_on_transfer` (triggering a NEP-141 refund) rather than consuming the tokens:

```rust
fn init_transfer(...) -> PromiseOrPromiseIndexOrValue<U128> {
    // Verify token is registered for the destination chain before consuming it
    require!(
        self.get_token_address(
            init_transfer_msg.get_destination_chain(),
            token_id.clone(),
        ).is_some(),
        BridgeError::TokenNotFound.as_ref()
    );
    // ... rest of function
}
```

Alternatively, add an admin-accessible `rescue_token` function that can transfer accidentally deposited unregistered tokens to a designated recovery address, analogous to the recommendation in the referenced Reservoir report.

---

### Proof of Concept

1. Deploy or use any NEP-141 token `unregistered-token.near` that is **not** in the bridge's `token_id_to_address` map.
2. Call `ft_transfer_call` on `unregistered-token.near` with `receiver_id = omni-bridge.near`, `amount = 1000`, and `msg = {"InitTransfer": {"recipient": "eth:0x...", "fee": "0", "native_token_fee": "0"}}`.
3. The bridge's `ft_on_transfer` is invoked. `init_transfer` runs without panicking, stores a pending transfer, and returns `U128(0)` — the 1000 tokens are now held by the bridge.
4. Call `sign_transfer` with the resulting `TransferId`. The call panics: `ERR_FAILED_TO_GET_TOKEN_ADDRESS`.
5. The 1000 tokens remain in the bridge's account permanently. No cancel or withdraw function exists to recover them. [5](#0-4) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-283)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
    }
```

**File:** near/omni-bridge/src/lib.rs (L462-469)
```rust
        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });
```

**File:** near/omni-bridge/src/lib.rs (L523-558)
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

**File:** near/CLAUDE.md (L57-70)
```markdown
**Key Functions:**
- `ft_on_transfer()` - Entry point for bridging (receives NEP-141 transfer from token contract)
- `fin_transfer()` - Finalize incoming transfer (requires proof, called by relayer)
- `sign_transfer()` - Request MPC signature for transfer (called by relayer)
- `deploy_token()` - Deploy bridged token on NEAR (requires proof, called by relayer)
- `bind_token()` - Register existing token as bridge-compatible (requires proof, called by relayer)
- `claim_fee()` - Claim accumulated fees (requires proof, called by relayer)

**UTXO Support (btc.rs):**
- `submit_transfer_to_utxo_chain_connector()` - Send to Bitcoin/Zcash (called by relayer)
- `rbf_increase_gas_fee()` - Replace-by-fee for stuck BTC transactions (DAO/RbfOperator only)

## omni-types

```
