### Title
Incomplete Mapping Update in `migrate_deployed_token` Leaves Stale Cross-Chain Token Bindings — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`migrate_deployed_token` updates token mappings only for the single `origin_chain` argument. Because a NEAR token can be registered on multiple foreign chains simultaneously (e.g., Eth **and** Base), the entries for every other chain remain bound to the now-invalid `old_token` account ID. After migration, any user who submits a `fin_transfer` proof from one of those other chains will have the NEAR-side finalization fail, permanently freezing their bridged funds.

---

### Finding Description

The `Contract` struct maintains two bidirectional maps for token identity:

- `token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>` — NEAR token ID → foreign address, per chain
- `token_address_to_id: LookupMap<OmniAddress, AccountId>` — foreign address → NEAR token ID [1](#0-0) 

A token is registered on a chain via `add_token`, which inserts into both maps: [2](#0-1) 

Because `add_token` is called once per chain (via `deploy_token_internal` or `bind_token_callback`), a single NEAR token account can accumulate entries for multiple chains:

```
token_id_to_address[(Eth, old_token)] = eth_address
token_id_to_address[(Base, old_token)] = base_address
token_address_to_id[eth_address]  = old_token
token_address_to_id[base_address] = old_token
```

`migrate_deployed_token` (DAO-only) is the legitimate admin path to replace `old_token` with `new_token`. It removes `old_token` from `deployed_tokens` / `deployed_tokens_v2`, then updates the mappings **only for the single `origin_chain` parameter**: [3](#0-2) 

After `migrate_deployed_token(Eth, old_token, new_token)`:

| Map | Key | Value | State |
|---|---|---|---|
| `deployed_tokens` | `old_token` | — | **removed** |
| `deployed_tokens` | `new_token` | — | inserted |
| `token_id_to_address` | `(Eth, old_token)` | — | **removed** |
| `token_id_to_address` | `(Eth, new_token)` | `eth_address` | inserted |
| `token_address_to_id` | `eth_address` | `new_token` | updated |
| `token_id_to_address` | `(Base, old_token)` | `base_address` | **STALE — not touched** |
| `token_address_to_id` | `base_address` | `old_token` | **STALE — not touched** |

The stale entries are never cleaned up.

---

### Impact Explanation

When a user submits a `fin_transfer` proof from the Base chain after the migration, the NEAR bridge resolves the token via `get_token_id`: [4](#0-3) 

`get_token_id(base_address)` returns `old_token` (the stale value). The bridge then checks `is_deployed_token(&old_token)`: [5](#0-4) 

`old_token` is no longer in `deployed_tokens`, so `is_deployed_token` returns `false`. The bridge falls through to the non-deployed branch and attempts an `ft_transfer` of `old_token` from its own balance — but the bridge holds no `old_token` balance (it was a minted/deployed token). The call panics or fails. The user's funds locked in the Base bridge contract cannot be released, and the NEAR-side finalization is permanently broken for that chain.

**Impact**: Permanent freezing of bridged funds for all users bridging from any chain other than `origin_chain` after a legitimate admin migration.

---

### Likelihood Explanation

- Multi-chain token deployments are the primary use case of the bridge; a NEAR token being live on both Ethereum and Base simultaneously is the expected production scenario.
- `migrate_deployed_token` is a DAO-level function intended for legitimate token upgrades (e.g., contract redeployments). No compromise is required — the admin is performing a routine operation.
- The stale state is permanent: there is no recovery path once the migration is executed, because `add_token` enforces `is_none()` on insert and would reject re-registration of `base_address`. [6](#0-5) 

---

### Recommendation

`migrate_deployed_token` must iterate over **all** chains on which `old_token` is registered and update every `(chain, old_token)` entry in `token_id_to_address` and the corresponding `token_address_to_id` entry. One approach:

1. Add a reverse index `token_id_to_chains: LookupMap<AccountId, Vec<ChainKind>>` so all chains for a given token ID can be enumerated.
2. In `migrate_deployed_token`, iterate over every `chain` in that set, remove `(chain, old_token)`, insert `(chain, new_token)`, and update `token_address_to_id[address_for_chain]` to `new_token`.
3. Also migrate `locked_tokens[(chain, old_token)]` → `locked_tokens[(chain, new_token)]` for every chain.

---

### Proof of Concept

1. Token `old_token.near` is deployed on NEAR originating from Eth, then bound to Base via `bind_token`. State:
   - `token_id_to_address[(Eth, old_token.near)] = 0xAAA...`
   - `token_id_to_address[(Base, old_token.near)] = 0xBBB...`
   - `token_address_to_id[0xBBB...] = old_token.near`
   - `deployed_tokens` contains `old_token.near`

2. DAO calls `migrate_deployed_token(Eth, old_token.near, new_token.near)`. After the call:
   - `deployed_tokens` no longer contains `old_token.near`
   - `token_id_to_address[(Base, old_token.near)] = 0xBBB...` ← stale, not removed
   - `token_address_to_id[0xBBB...] = old_token.near` ← stale, not updated

3. User bridges 1000 USDC from Base chain. Relayer submits `fin_transfer` proof on NEAR.

4. `get_token_id(OmniAddress::Base(0xBBB...))` → `old_token.near` (stale).

5. `is_deployed_token(&old_token.near)` → `false`.

6. Bridge attempts `ft_transfer(old_token.near, recipient, 1000)` — bridge holds zero `old_token.near` balance → call fails.

7. User's 1000 USDC remain locked in the Base bridge contract with no recovery path. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L226-228)
```rust
    pub token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>,
    pub token_address_to_id: LookupMap<OmniAddress, AccountId>,
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
```

**File:** near/omni-bridge/src/lib.rs (L1356-1358)
```rust
    pub fn is_deployed_token(&self, token: &AccountId) -> bool {
        self.deployed_tokens.contains(token) || self.deployed_tokens_v2.contains_key(token)
    }
```

**File:** near/omni-bridge/src/lib.rs (L1368-1376)
```rust
    pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
        if let OmniAddress::Near(token_account_id) = address {
            token_account_id.clone()
        } else {
            self.token_address_to_id
                .get(address)
                .near_expect(BridgeError::TokenNotRegistered)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1604-1664)
```rust
    #[access_control_any(roles(Role::DAO))]
    #[payable]
    pub fn migrate_deployed_token(
        &mut self,
        origin_chain: ChainKind,
        old_token: AccountId,
        new_token: AccountId,
    ) {
        require!(
            env::attached_deposit() >= NEP141_DEPOSIT,
            BridgeError::NotEnoughAttachedDeposit.as_ref()
        );

        require!(
            self.deployed_tokens.remove(&old_token),
            BridgeError::OldTokenNotDeployed.as_ref(),
        );
        require!(
            self.deployed_tokens.insert(&new_token),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2.remove(&old_token);
        self.deployed_tokens_v2.insert(&new_token, &origin_chain);

        let origin_address = self
            .token_id_to_address
            .remove(&(origin_chain, old_token.clone()))
            .near_expect(BridgeError::FailedToGetTokenAddress);

        require!(
            self.token_id_to_address
                .insert(&(origin_chain, new_token.clone()), &origin_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );

        self.token_address_to_id
            .insert(&origin_address, &new_token)
            .near_expect(BridgeError::ExpectedToOverwriteTokenAddress);

        require!(
            self.migrated_tokens
                .insert(&old_token, &new_token)
                .is_none(),
            BridgeError::TokenAlreadyMigrated.as_ref()
        );

        ext_token::ext(new_token.clone())
            .with_static_gas(STORAGE_DEPOSIT_GAS)
            .with_attached_deposit(NEP141_DEPOSIT)
            .storage_deposit(&env::current_account_id(), Some(true))
            .detach();

        env::log_str(
            &OmniBridgeEvent::MigrateTokenEvent {
                old_token_id: old_token,
                new_token_id: new_token,
            }
            .to_log_string(),
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L2704-2736)
```rust
    fn add_token(
        &mut self,
        token_id: &AccountId,
        token_address: &OmniAddress,
        decimals: u8,
        origin_decimals: u8,
    ) {
        let chain_kind = token_address.get_chain();
        require!(
            self.token_id_to_address
                .insert(&(chain_kind, token_id.clone()), token_address)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_address_to_id
                .insert(token_address, token_id)
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
        require!(
            self.token_decimals
                .insert(
                    token_address,
                    &Decimals {
                        decimals,
                        origin_decimals,
                    }
                )
                .is_none(),
            BridgeError::TokenExists.as_ref()
        );
    }
```
