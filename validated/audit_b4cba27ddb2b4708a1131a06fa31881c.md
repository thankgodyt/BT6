### Title
Unprotected Initialization Allows Attacker to Seize Controller and Bridge Roles — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `nbtc` token contract's `new()` initializer accepts arbitrary `controller` and `bridge_id` parameters from any caller. The only guard is `require!(!env::state_exists(), "Already initialized")`, which prevents re-initialization but does not prevent a front-running attacker from calling `new()` before the legitimate deployer does, seizing both the controller role and the bridge identity, and subsequently minting unbacked nBTC.

### Finding Description
`contracts/nbtc/src/lib.rs` lines 58–91 define the sole initializer:

```rust
#[init]
pub fn new(
    controller: AccountId,
    bridge_id: AccountId,
    ...
) -> Self {
    require!(!env::state_exists(), "Already initialized");
    ...
    contract.token.internal_register_account(&contract.bridge_id);
    contract
}
``` [1](#0-0) 

There is no check that `env::predecessor_account_id()` is the contract deployer or any other trusted account. Any NEAR account that calls `new()` before the deployer does will have its supplied `controller` and `bridge_id` values written into contract state permanently.

The `mint()` and `burn()` functions are gated only by `assert_bridge()`:

```rust
fn assert_bridge(&self) {
    require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
}
``` [2](#0-1) 

If the attacker supplies their own account as `bridge_id`, they satisfy `assert_bridge()` and can call `mint()` freely.

The same class of issue exists in `contracts/satoshi-bridge/src/lib.rs` `new()`, where the caller unconditionally becomes the ACL super-admin and DAO role holder:

```rust
contract.acl_init_super_admin(env::predecessor_account_id());
contract.acl_grant_role(Role::DAO.into(), env::predecessor_account_id());
``` [3](#0-2) 

### Impact Explanation
An attacker who wins the initialization race on the `nbtc` contract can:
1. Set `bridge_id` to their own account.
2. Call `mint()` with arbitrary `mint_account_id` and `mint_amount`, minting unbacked nBTC to any recipient.
3. Retain `controller` to block any recovery via `set_controller()`.

This constitutes **unauthorized minting of nBTC** — a Critical-class impact.

### Likelihood Explanation
In NEAR Protocol, contract deployment and initialization are separate transactions unless the deployer explicitly batches them. If the deployer issues a `DeployContract` action and then a separate function-call transaction to `new()`, there is a block-level window in which any observer can submit their own `new()` call. NEAR does not have a traditional mempool, but block producers see all pending transactions and a malicious validator or a well-timed attacker can exploit this gap. Likelihood is **Low-to-Medium**: the window is narrow but the code provides no protection whatsoever.

### Recommendation
Restrict the initializer to the contract's own account (the deployer) by asserting the predecessor at the start of `new()`:

```rust
require!(
    env::predecessor_account_id() == env::current_account_id(),
    "Only the contract account may initialize"
);
```

Alternatively, batch the `DeployContract` and `new()` call into a single NEAR transaction so no external account can interpose. Apply the same fix to `satoshi-bridge`'s `new()`.

### Proof of Concept
1. Deployer submits `DeployContract` for `nbtc` (transaction A).
2. Before the deployer's follow-up `new(legitimate_controller, legitimate_bridge, ...)` transaction is included, attacker submits:
   ```
   nbtc.new(
       controller = "attacker.near",
       bridge_id  = "attacker.near",
       name       = "nBTC",
       symbol     = "nBTC",
       decimals   = 8
   )
   ```
3. Attacker's `new()` is processed first; state is written with `bridge_id = "attacker.near"`.
4. Deployer's `new()` panics: `"Already initialized"`.
5. Attacker calls `nbtc.mint(mint_account_id="attacker.near", mint_amount=U128(MAX), ...)` from `"attacker.near"` — `assert_bridge()` passes, unbacked nBTC is minted. [4](#0-3)

### Citations

**File:** contracts/nbtc/src/lib.rs (L58-91)
```rust
    #[init]
    pub fn new(
        controller: AccountId,
        bridge_id: AccountId,
        name: String,
        symbol: String,
        icon: Option<String>,
        decimals: u8,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut contract = Self {
            controller,
            bridge_id,
            token: FungibleToken::new(StorageKey::FungibleToken),
            metadata: LazyOption::new(
                StorageKey::Metadata,
                Some(&FungibleTokenMetadata {
                    spec: FT_METADATA_SPEC.to_string(),
                    name,
                    symbol,
                    icon,
                    reference: None,
                    reference_hash: None,
                    decimals,
                }),
            ),
        };

        contract
            .token
            .internal_register_account(&contract.bridge_id);

        contract
    }
```

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L332-334)
```rust
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L220-221)
```rust
        contract.acl_init_super_admin(env::predecessor_account_id());
        contract.acl_grant_role(Role::DAO.into(), env::predecessor_account_id());
```
