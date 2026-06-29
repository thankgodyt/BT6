### Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-funding in `init_transfer` — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

The `NativeFeeRestricted` role check in `init_transfer` is only evaluated in one branch of a two-branch OR condition. The first branch — `try_to_transfer_balance_from_message_account` — carries no role check at all. Because the message storage account ID is fully deterministic and publicly computable before the transfer is submitted, a `NativeFeeRestricted` user can pre-fund that virtual account and force execution into the unchecked branch, bypassing the restriction entirely.

---

### Finding Description

`init_transfer` (lines 566–618) decides how to proceed via the following condition:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // ← Branch A — NO role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(&signer_id, ...)
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
    // ↑ Branch B — role check lives here only
{
    self.init_transfer_internal(transfer_message, signer_id)   // ← reached from BOTH branches
} else {
    // yield path → init_transfer_resume (also no role check)
}
``` [1](#0-0) 

The `NativeFeeRestricted` check (`acl_has_role`) is placed exclusively inside Branch B. Branch A (`try_to_transfer_balance_from_message_account`) has no such guard. If Branch A returns `Ok`, execution falls directly into `init_transfer_internal` with whatever `native_fee` the user specified — the role is never consulted.

The same gap exists in `init_transfer_resume` (the yield/resume path): it calls `try_to_transfer_balance_from_message_account` and, on success, calls `init_transfer_internal` with no role check. [2](#0-1) 

The message storage account ID is computed deterministically from publicly known transfer parameters (token, amount, recipient, fee, sender, msg) via `TransferMessageStorageAccount::id()`: [3](#0-2) 

Nonces are explicitly excluded from the hash, so the account ID can be computed before the transfer is submitted: [4](#0-3) 

---

### Impact Explanation

`NativeFeeRestricted` is a compliance role that prevents designated accounts from attaching a native NEAR fee to their outbound transfers. [5](#0-4) 

By bypassing this restriction, a `NativeFeeRestricted` user can:
- Attach an arbitrary native NEAR fee to their transfer, incentivizing relayers to process it.
- Circumvent the compliance control entirely, defeating the purpose of the role.

This is a **role/authorization bypass** — the direct analog of the external report's FULL_RESTRICTED deposit bypass. The attacker-controlled entry path is fully reachable by any unprivileged bridge user who has been assigned the `NativeFeeRestricted` role.

---

### Likelihood Explanation

Exploitation requires only two on-chain calls:
1. `storage_deposit` targeting the pre-computed virtual account ID.
2. `ft_transfer_call` with a non-zero `native_token_fee`.

The virtual account ID is deterministic and computable off-chain before the transfer is submitted (nonces are not part of the hash). No privileged access, leaked keys, or external dependency is required. Any `NativeFeeRestricted` user can execute this independently.

---

### Recommendation

Move the `NativeFeeRestricted` role check to a position that is evaluated unconditionally, before the branching logic, whenever `native_token_fee > 0`:

```rust
if init_transfer_msg.native_token_fee.0 > 0 {
    require!(
        !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
        BridgeError::OperationNotAllowed.as_ref()
    );
}
```

This ensures the restriction is enforced regardless of which storage-payment path is taken, including the yield/resume path in `init_transfer_resume`.

---

### Proof of Concept

```
1. Admin grants NativeFeeRestricted role to attacker.near.

2. Attacker computes the virtual message storage account ID off-chain:
   TransferMessageStorageAccount {
       token:     Near("token.near"),
       amount:    U128(1_000),
       recipient: Eth(0xDEAD...),
       fee:       Fee { fee: U128(0), native_fee: U128(1_000_000_000_000_000_000_000_000) },
       sender:    Near("attacker.near"),
       msg:       "",
   }.id(None)
   → deterministic hex account ID (e.g., "a3f7...c2d1")

3. Attacker calls:
   bridge.storage_deposit({ account_id: "a3f7...c2d1" })
   with deposit = native_fee + required_storage_balance

4. Attacker calls:
   token.ft_transfer_call({
       receiver_id: "bridge.near",
       amount: "1000",
       msg: InitTransferMsg { native_token_fee: "1000000000000000000000000", ... }
   })

5. Inside init_transfer:
   - try_to_transfer_balance_from_message_account("a3f7...c2d1", ...) → Ok(())  ← Branch A succeeds
   - NativeFeeRestricted check is NEVER reached
   - init_transfer_internal is called with native_fee = 1 NEAR

6. Transfer is registered with a non-zero native fee, bypassing the restriction.
   Relayers are now incentivized to process the restricted user's transfer.
```

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

**File:** near/omni-bridge/src/lib.rs (L566-584)
```rust
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
```

**File:** near/omni-bridge/src/lib.rs (L635-645)
```rust
        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }

        self.init_transfer_internal(transfer_message, storage_owner)
```

**File:** near/omni-types/src/lib.rs (L599-634)
```rust
#[near(serializers=[borsh])]
#[derive(Debug, Clone)]
pub struct TransferMessageStorageAccount {
    pub token: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub sender: OmniAddress,
    pub msg: String,
}

impl TransferMessageStorageAccount {
    #[allow(clippy::missing_panics_doc)]
    pub fn id(&self, external_id: Option<String>) -> AccountId {
        let mut bytes = borsh::to_vec(self).unwrap();
        if let Some(external_id) = external_id {
            bytes.extend_from_slice(external_id.as_bytes());
        }
        let hash = utils::sha256(&bytes);
        let implicit_account_id = hex::encode(hash);
        AccountId::try_from(implicit_account_id).unwrap()
    }
}

impl From<TransferMessage> for TransferMessageStorageAccount {
    fn from(value: TransferMessage) -> Self {
        Self {
            token: value.token,
            amount: value.amount,
            recipient: value.recipient,
            fee: value.fee,
            sender: value.sender,
            msg: value.msg,
        }
    }
}
```
