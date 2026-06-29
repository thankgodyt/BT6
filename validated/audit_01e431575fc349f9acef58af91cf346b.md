### Title
Asymmetric Pause Bypass Between `ft_on_transfer` and `sign_transfer` Permanently Freezes Funds for `UnrestrictedDeposit` Role Holders During Pause - (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR `omni-bridge` contract grants `Role::UnrestrictedDeposit` the ability to bypass the global pause on `ft_on_transfer` (the transfer initiation path), but the corresponding transfer completion function `sign_transfer` only allows `Role::DAO` to bypass the pause. This asymmetry means that a user with `UnrestrictedDeposit` can lock or burn their tokens and create a pending transfer while the bridge is paused, but no relayer can ever call `sign_transfer` to release those tokens on the destination chain during the same pause. There is no cancel or refund mechanism for pending transfers, so the funds are frozen until the DAO manually intervenes.

---

### Finding Description

`ft_on_transfer` is decorated with:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String)
```

This allows any account holding `Role::UnrestrictedDeposit` to call `ft_on_transfer` even when the bridge is globally paused. When an `InitTransfer` message is parsed, the function calls `init_transfer_internal`, which either **burns** the user's deployed tokens or **locks** native tokens in the bridge, and stores the pending `TransferMessage`.

`sign_transfer`, the function that a trusted relayer must call to produce the MPC signature that releases funds on the destination chain, is decorated with:

```rust
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn sign_transfer(&mut self, transfer_id: TransferId, fee_recipient: Option<AccountId>, fee: &Option<Fee>) -> Promise
```

`Role::UnrestrictedDeposit` is **not** listed in the `except` clause of `sign_transfer`. During a pause, only `Role::DAO` can call `sign_transfer`. Trusted relayers — the normal actors who call `sign_transfer` — are blocked. There is no cancel or refund path for a pending transfer in the contract.

---

### Impact Explanation

A user with `Role::UnrestrictedDeposit` initiates a NEAR→Foreign transfer while the bridge is paused. Their tokens are immediately burned (for deployed bridge tokens) or locked. The `TransferMessage` is stored in `pending_transfers`. Because `sign_transfer` is paused for everyone except `Role::DAO`, no relayer can produce the MPC signature needed to release funds on the destination chain. The user's tokens are destroyed on NEAR with no corresponding release on the destination chain and no way to recover them without DAO intervention. If the DAO does not notice or act, the funds are permanently frozen or lost.

---

### Likelihood Explanation

`Role::UnrestrictedDeposit` is explicitly designed to allow privileged depositors to operate during a pause — this is a documented, intentional feature. A pause event is a realistic operational scenario (security incident, upgrade, etc.). Any account holding `UnrestrictedDeposit` that initiates a transfer during a pause will trigger this condition. The asymmetry is structural and requires no attacker; it is triggered by normal use of the `UnrestrictedDeposit` privilege.

---

### Recommendation

Add `Role::UnrestrictedDeposit` (or a dedicated `Role::UnrestrictedRelayer`) to the `except` clause of `sign_transfer` to mirror the bypass granted on `ft_on_transfer`:

```rust
#[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
pub fn sign_transfer(...) -> Promise
```

Alternatively, implement a cancel/refund path for pending transfers so that a user whose transfer cannot be signed can recover their tokens.

---

### Proof of Concept

1. Admin pauses the bridge (e.g., via `PauseManager` role).
2. Account `alice` holds `Role::UnrestrictedDeposit`.
3. `alice` calls `ft_transfer_call` on a deployed bridge token, routing to `ft_on_transfer` with an `InitTransfer` message targeting an EVM chain.
4. `ft_on_transfer` passes the pause check because `UnrestrictedDeposit` is in the `except` list. `init_transfer_internal` is called: alice's tokens are **burned** and a `TransferMessage` is stored in `pending_transfers`.
5. A trusted relayer attempts to call `sign_transfer` for alice's `TransferId`.
6. `sign_transfer` fails the pause check — only `Role::DAO` is in its `except` list. The relayer is rejected.
7. Alice's tokens are burned on NEAR. No MPC signature is produced. No funds are released on the destination chain. There is no cancel function. Alice's funds are frozen.

**Relevant code references:**

`ft_on_transfer` pause bypass grants `UnrestrictedDeposit`: [1](#0-0) 

`sign_transfer` pause bypass grants only `DAO`: [2](#0-1) 

Token burn executed unconditionally inside `init_transfer_internal` before any signing occurs: [3](#0-2) 

Role definitions confirming `UnrestrictedDeposit` and `DAO` are separate roles: [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L113-129)
```rust
#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    DAO,
    PauseManager,
    UnrestrictedDeposit,
    UpgradableCodeStager,
    UpgradableCodeDeployer,
    MetadataManager,
    UnrestrictedRelayer,
    TokenControllerUpdater,
    NativeFeeRestricted,
    RbfOperator,
    TokenUpgrader,
    TokenLockController,
    RelayerManager,
}
```

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L1850-1851)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
```
