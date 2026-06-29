### Title
No User-Callable Escape Mechanism for Pending Outbound Transfers Allows Trusted Relayers to Permanently Freeze User Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary
When a user initiates an outbound transfer (NEAR → EVM/Solana/Starknet/BTC), their tokens are immediately and irrevocably locked or burned inside the bridge contract. The only function that can advance the transfer — `sign_transfer` — is exclusively gated behind the `#[trusted_relayer]` macro. No user-callable cancel or refund path exists. A trusted relayer that selectively ignores a specific user's transfer, or a scenario where the entire trusted-relayer set becomes empty, permanently freezes the user's bridged funds with no on-chain remedy.

### Finding Description

**Outbound transfer flow:**

1. User calls `ft_transfer_call` on the token contract → `ft_on_transfer` → `init_transfer` → `init_transfer_internal`.
2. Inside `init_transfer_internal`, tokens are immediately burned (for bridge-deployed tokens) or locked via `lock_tokens_if_needed`, and the `TransferMessage` is stored in `pending_transfers`.
3. The transfer can only be advanced by a **trusted relayer** calling `sign_transfer`, which requests an MPC signature and emits the `SignTransferEvent` that the destination chain listens for.

`sign_transfer` carries two independent guards that together make it exclusively relayer-callable:

```rust
// near/omni-bridge/src/lib.rs:444-447
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn sign_transfer(...)
```

The `#[trusted_relayer]` macro (applied at the impl-block level with `bypass_roles(Role::DAO, Role::UnrestrictedRelayer)`) rejects any caller that is not an active trusted relayer, DAO, or `UnrestrictedRelayer`. Ordinary users are never in any of those sets.

Token locking/burning happens unconditionally before any relayer involvement:

```rust
// near/omni-bridge/src/lib.rs:1850-1857
if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
    self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
    self.lock_tokens_if_needed(
        transfer_message.get_destination_chain(),
        &token_id,
        transfer_message.amount.0,
    );
```

There is **no `cancel_transfer`, `withdraw_pending_transfer`, or any other user-callable function** that removes a `TransferMessage` from `pending_transfers` and returns the locked/burned tokens to the user. The only removal paths are:

- `sign_transfer_callback` removes the message only when `fee.is_zero()` and the MPC signing succeeded — both require a relayer to have already called `sign_transfer`.
- `claim_fee_callback` / `remove_transfer_message` — also relayer-initiated.
- `transfer_token_as_dao` — DAO-only emergency escape, not user-callable.

The same relayer gate applies to inbound transfers: `fin_transfer` is also `#[trusted_relayer]`-gated, so a user bridging from EVM → NEAR also cannot self-serve finalization.

**Censorship vectors that do not require any compromise:**

| Vector | Mechanism |
|---|---|
| Selective per-user censorship | A trusted relayer simply never calls `sign_transfer` for a targeted user's `TransferId`. No on-chain action required. |
| Full relayer set depletion | All relayers call `resign_trusted_relayer` (legitimate, stake is returned). No new relayer is required to apply. |
| DAO revocation | DAO calls `reject_relayer_application` on every active relayer (stake is confiscated, not returned to relayer). |
| Pause + no DAO action | `PauseManager` pauses the contract; `sign_transfer` is blocked for all non-DAO callers indefinitely. |

### Impact Explanation

Once `init_transfer_internal` executes, the user's tokens are gone from their wallet. If no trusted relayer ever calls `sign_transfer` for that `TransferId`, the `TransferMessage` sits in `pending_transfers` forever and the tokens are permanently frozen inside the bridge (burned supply is unrecoverable; locked native tokens are inaccessible). This matches the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation

The trusted-relayer set is permissioned. Any single active relayer can selectively censor any individual user's transfer at zero cost (simply by not submitting the transaction). The user has no on-chain recourse. A user could theoretically apply to become a relayer themselves, but this requires staking 1,000 NEAR and waiting the default 7-day activation period (`waiting_period_ns = 604_800_000_000_000`), and the DAO can reject the application and confiscate the stake. The censorship is therefore durable and economically asymmetric.

### Recommendation

Implement a user-callable `cancel_transfer` function that:
1. Verifies `env::predecessor_account_id()` matches `transfer_message.sender` (the original depositor).
2. Optionally enforces a minimum age on the pending transfer (e.g., 24 hours) to prevent front-running of legitimate relayer processing.
3. For locked native tokens: calls `unlock_tokens_if_needed` and returns the tokens via `ft_transfer`.
4. For burned bridge-deployed tokens: mints the equivalent amount back to the sender.
5. Removes the entry from `pending_transfers`.

This mirrors the Linea recommendation: provide a mechanism for users to retrieve their assets without depending on the privileged intermediary.

### Proof of Concept

1. User calls `ft_transfer_call` on `token.near` with `msg = InitTransferMsg { recipient: EVM_ADDR, fee: 0, ... }` targeting `omni.bridge.near`.
2. `ft_on_transfer` → `init_transfer` → `init_transfer_internal` executes: tokens are burned/locked, `TransferMessage` stored at `TransferId { origin_chain: Near, origin_nonce: N }`.
3. The single active trusted relayer is the bridge operator. The operator calls `resign_trusted_relayer`, recovering their stake. The trusted-relayer set is now empty.
4. No account can call `sign_transfer` (all callers fail the `#[trusted_relayer]` check; DAO is the only bypass but is a separate privileged party).
5. The user's tokens are permanently frozen. `get_transfer_message({ origin_chain: Near, origin_nonce: N })` still returns the message indefinitely. No user-callable function exists to recover the funds. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L670-696)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
        require!(
            args.storage_deposit_actions.len() <= 3,
            BridgeError::InvalidStorageAccountsLen.as_ref()
        );
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
    }
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
