### Title
`finish_withdraw_v2` Missing `#[pause]` Guard Allows Pause Bypass for Outbound Transfer Initiation — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`finish_withdraw_v2` is a public state-mutating function in the NEAR `omni-bridge` contract that creates and queues outbound `TransferMessage` entries. Unlike every other state-changing public function in the same contract, it carries no `#[pause]` attribute. When the bridge operator pauses the contract to halt operations during a security incident, any holder of a deployed-token balance can still trigger the token contract to call `finish_withdraw_v2`, queuing outbound transfers that will be signed and executed once the bridge is unpaused.

---

### Finding Description

Every externally reachable, state-mutating function in `Contract` is decorated with a pause guard:

| Function | Guard |
|---|---|
| `ft_on_transfer` | `#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]` |
| `log_metadata` | `#[pause(except(roles(Role::DAO)))]` |
| `update_transfer_fee` | `#[pause]` |
| `sign_transfer` | `#[pause(except(roles(Role::DAO)))]` |
| `fin_transfer` | `#[pause(except(roles(Role::DAO)))]` |
| `claim_fee` | `#[pause(except(roles(Role::DAO)))]` |
| `deploy_token` | `#[pause(except(roles(Role::DAO)))]` |
| `bind_token` | `#[pause(except(roles(Role::DAO)))]` |

`finish_withdraw_v2` has **none**: [1](#0-0) 

The function is `pub`, accepts caller-supplied `sender_id`, `amount`, and `recipient`, and its only guard is: [2](#0-1) 

which verifies only that `env::predecessor_account_id()` is a registered deployed token — not that the bridge is unpaused. It then unconditionally increments `current_origin_nonce`, allocates a `destination_nonce`, inserts a `TransferMessage` into `pending_transfers`, and emits an `InitTransferEvent`: [3](#0-2) 

The pause system is provided by `near-plugins` and is applied via the `#[pause]` proc-macro attribute. Its absence here means the `Pausable` state is never consulted. [4](#0-3) 

---

### Impact Explanation

When the bridge is paused (e.g., in response to an active exploit or a critical bug), the operator's intent is to freeze all outbound transfer initiation. Because `finish_withdraw_v2` bypasses the pause:

1. A user holding tokens in any deployed `OmniToken` contract can trigger that contract to call `finish_withdraw_v2` on the bridge, queuing an outbound `TransferMessage` with an arbitrary `recipient` on Ethereum.
2. The queued message persists in `pending_transfers` across the pause period.
3. Once the bridge is unpaused, a relayer calls `sign_transfer` (which is properly paused during the incident but becomes callable again), obtains an MPC signature, and the transfer is finalized on the destination chain — draining the corresponding locked or minted tokens.

This constitutes a **pause bypass** enabling unauthorized outbound transfer initiation, matching the "authorization bypass / pause bypass" impact class.

---

### Likelihood Explanation

- The entry path requires only that the caller holds a balance in any deployed `OmniToken` and can trigger the token contract's legacy withdrawal flow (the "Near Intents" path referenced in the code comments).
- No admin compromise, key leak, or privileged role is needed.
- The bridge is paused precisely when an incident is occurring, making this the highest-value window for exploitation.
- The function is labeled a "legacy" flow, suggesting it may not receive the same review attention as newer paths.

---

### Recommendation

Add the same pause guard used by all other state-mutating functions:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn finish_withdraw_v2(
    &mut self,
    ...
```

If the legacy flow must remain callable during a pause for user-fund-safety reasons (e.g., tokens are burned before this call and users would lose funds otherwise), document that exception explicitly and add a role-gated bypass analogous to `Role::UnrestrictedDeposit` used in `ft_on_transfer`.

---

### Proof of Concept

1. Operator pauses the bridge (e.g., `pause_all()` or targeted pause via `PauseManager`).
2. Attacker holds tokens in a deployed `OmniToken` (e.g., `eth-usdc.omni.near`).
3. Attacker triggers the token contract's legacy withdrawal mechanism, causing it to call `finish_withdraw_v2` on the bridge with `amount = X` and `recipient = attacker_eth_address`.
4. `finish_withdraw_v2` executes without consulting the pause state, inserts the `TransferMessage` into `pending_transfers`, and emits `InitTransferEvent`.
5. Bridge is unpaused after the incident is believed resolved.
6. Relayer calls `sign_transfer` for the queued transfer; MPC signs it; attacker receives `X` tokens on Ethereum. [1](#0-0)

### Citations

**File:** near/omni-bridge/src/lib.rs (L209-212)
```rust
#[near(contract_state)]
#[derive(Pausable, Upgradable, PanicOnDefault)]
#[access_control(role_type(Role))]
#[pausable(manager_roles(Role::PauseManager))]
```

**File:** near/omni-bridge/src/lib.rs (L1314-1354)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_withdraw_v2(
        &mut self,
        #[serializer(borsh)] sender_id: &AccountId,
        #[serializer(borsh)] amount: u128,
        #[serializer(borsh)] recipient: String,
    ) {
        let token_id = env::predecessor_account_id();
        require!(self.is_deployed_token(&token_id),);

        self.current_origin_nonce += 1;
        let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount: U128(amount),
            recipient: OmniAddress::Eth(
                H160::from_str(&recipient).near_expect(BridgeError::InvalidRecipientAddress),
            ),
            fee: Fee {
                fee: U128(0),
                native_fee: U128(0),
            },
            sender: OmniAddress::Near(sender_id.clone()),
            msg: String::new(),
            destination_nonce,
            origin_transfer_id: None,
        };

        let required_storage_balance =
            self.add_transfer_message(transfer_message.clone(), sender_id.clone());

        self.update_storage_balance(
            env::current_account_id(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
    }
```
