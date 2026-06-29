### Title
Untrusted External `decimals()` / `ft_metadata()` Return Value Permanently Poisons NEAR's Normalization Factor — (`starknet/src/omni_bridge.cairo`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `near/omni-bridge/src/lib.rs`)

---

### Summary

The `log_metadata` entry points on Starknet, EVM, and NEAR are permissionless. Each one reads `decimals()` (or `ft_metadata().decimals`) from an arbitrary, caller-supplied token contract and emits the result as a `LogMetadata` event. NEAR's `deploy_token_callback` consumes that event and permanently writes the decimals into the `token_decimals` storage map. Every subsequent `normalize_amount` and `denormalize_amount` call for that token uses the stored value. A malicious token deployer can make `decimals()` return a value that differs from the token's true precision, permanently corrupting the normalization factor and causing all future cross-chain transfers of that token to carry wrong amounts.

---

### Finding Description

**Starknet entry point** (`starknet/src/omni_bridge.cairo:144-200`):

```cairo
fn log_metadata(ref self: ContractState, token: ContractAddress) {
    ...
    let decimals = {
        let mut res = syscalls::call_contract_syscall(
            token, selector!("decimals"), call_data.span(),
        ).unwrap_syscall();
        Serde::<u8>::deserialize(ref res).expect(...)
    };
    self.emit(Event::LogMetadata(LogMetadata { address: token, name, symbol, decimals }))
}
```

`log_metadata` is public with no access control. The `token` argument is fully attacker-controlled. The `decimals` value returned by the external call is emitted verbatim.

**EVM entry point** (`evm/src/omni-bridge/contracts/OmniBridge.sol:224-232`):

```solidity
function logMetadata(address tokenAddress) external payable {
    string memory name  = IERC20Metadata(tokenAddress).name();
    string memory symbol = IERC20Metadata(tokenAddress).symbol();
    uint8 decimals = IERC20Metadata(tokenAddress).decimals();
    ...
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
```

Same pattern: permissionless, arbitrary `tokenAddress`, single external call, result emitted.

**NEAR entry point** (`near/omni-bridge/src/lib.rs:316-384`):

```rust
pub fn log_metadata(&self, token_id: &AccountId) -> Promise {
    ext_token::ext(token_id.clone())
        .ft_metadata()
        .then(Self::ext(...).log_metadata_callback(token_id))
}

pub fn log_metadata_callback(&self, #[callback] metadata: FungibleTokenMetadata, ...) {
    let metadata_payload = MetadataPayload {
        decimals: metadata.decimals,   // ← from untrusted token
        ...
    };
    // MPC signs this payload; result is broadcast to EVM/Starknet/Solana
}
```

**Permanent storage** (`near/omni-bridge/src/lib.rs:1147-1175`, `2397-2419`):

```rust
pub fn deploy_token_callback(...) {
    let Ok(ProverResult::LogMetadata(metadata)) = call_result else { ... };
    self.deploy_token_internal(chain, &metadata.token_address,
        BasicMetadata { decimals: metadata.decimals, ... }, ...)
}

fn deploy_token_internal(..., metadata: BasicMetadata, ...) {
    self.add_token(&token_id, token_address,
        metadata.decimals,   // stored as `decimals`
        metadata.decimals,   // stored as `origin_decimals`
    );
}
```

**Normalization uses the stored value** (`near/omni-bridge/src/lib.rs:2776-2787`):

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))
}
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

These are called in `sign_transfer` (line 475) and `fin_transfer_callback` (line 725) for every cross-chain transfer of the token.

---

### Impact Explanation

Once the wrong `decimals` value is written into `token_decimals`, it cannot be corrected by any unprivileged actor. Every transfer of that token is scaled by the wrong power of ten:

- If `origin_decimals` is reported as **higher** than the true value (e.g., 24 instead of 18), `normalize_amount` divides by an extra `10^6`, so users bridging out receive only `1/10^6` of the expected EVM/Starknet amount — a 99.9999 % loss.
- If `origin_decimals` is reported as **lower** than the true value (e.g., 6 instead of 18), `denormalize_amount` multiplies by a smaller factor, so users bridging back to NEAR receive far fewer tokens than they locked on the source chain.

Both directions constitute permanent, irreversible balance manipulation for every user who bridges the affected token.

---

### Likelihood Explanation

The entry path is fully permissionless. Any account can:

1. Deploy a Starknet or EVM token whose `decimals()` selector returns an attacker-chosen value.
2. Call `log_metadata` / `logMetadata` on the bridge with that token address.
3. Submit the resulting proof to NEAR's `deploy_token`, permanently registering the wrong normalization factor.

No admin action, no private key, no oracle, and no threshold-signature compromise is required. The only prerequisite is deploying a token contract, which is a standard, permissionless operation on both Starknet and EVM.

---

### Recommendation

1. **Validate decimals at registration time.** After reading `decimals()` from the external token, assert that the value falls within a sane range (e.g., 1–24) and, where possible, cross-check it against a second independent call or a known registry.
2. **Cache and freeze.** The current code already caches the value in `token_decimals`, but there is no guard preventing a second `log_metadata` call from overwriting it via a new `deploy_token` invocation for the same address. Add an explicit check that `token_decimals` is not already set before writing.
3. **Emit the stored value, not the raw external value.** Log the value that was actually written to storage so that off-chain monitors can detect discrepancies between the emitted decimals and the on-chain token's current `decimals()`.
4. **Consider an allowlist or governance step** before a new token's normalization factor is accepted, analogous to the `factories` allowlist already used for emitter addresses.

---

### Proof of Concept

**Starknet path:**

```cairo
// Attacker deploys this contract on Starknet
#[starknet::contract]
mod MaliciousToken {
    #[external(v0)]
    fn decimals(self: @ContractState) -> u8 { 24_u8 }  // true precision is 18
    fn name(...)   -> ByteArray { "Evil" }
    fn symbol(...) -> ByteArray { "EVL" }
    // standard ERC-20 transfer / transfer_from / etc.
}
```

1. Attacker calls `OmniBridge::log_metadata(malicious_token_address)` on Starknet.
2. Bridge emits `LogMetadata { address: malicious_token, decimals: 24 }`.
3. Relayer submits proof to NEAR `deploy_token` → `deploy_token_callback` stores `decimals = 24, origin_decimals = 24`.
4. Victim bridges 1 token (10^18 units, true 18-decimal precision) from Starknet to NEAR.
5. NEAR's `fin_transfer_callback` calls `denormalize_amount(10^18, {24, 24})` → `diff = 0` → victim receives 10^18 units. *(Symmetric case — no loss here.)*
6. Victim bridges back: NEAR `sign_transfer` calls `normalize_amount(10^18, {24, 24})` → `diff = 0` → Starknet receives 10^18 units. *(Still symmetric.)*

**The damaging case — mismatched `origin_decimals` via NEAR `log_metadata`:**

1. Attacker deploys a NEAR NEP-141 token whose `ft_metadata()` returns `decimals: 24` but whose actual balances are denominated in 18-decimal units.
2. Calls NEAR `log_metadata(malicious.near)` → MPC signs `MetadataPayload { decimals: 24 }`.
3. EVM `deployToken` is called with the signed payload → `_normalizeDecimals(24) = 18` → EVM token deployed with 18 decimals; `DeployToken` event emits `decimals = 18, originDecimals = 24`.
4. NEAR `bind_token_callback` stores `decimals = 18, origin_decimals = 24` → `diff_decimals = 6`.
5. Victim holds 1 NEAR token (10^18 units, true 18-decimal) and bridges to EVM.
6. `normalize_amount(10^18, {18, 24}) = 10^18 / 10^6 = 10^12`.
7. EVM receives 10^12 units of an 18-decimal token = **0.000001 EVM tokens**.
8. Victim has lost **99.9999 %** of their bridged value with no recourse. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** starknet/src/omni_bridge.cairo (L144-200)
```text
        fn log_metadata(ref self: ContractState, token: ContractAddress) {
            // There are two possible metadata standards in use.
            // 1. Old style: name and symbol are felt252 values.
            // 2. New style: name and symbol are ByteArray values (ERC20 ABI).
            // We are using low-level contract calls to determine the type.

            let call_data: Array<felt252> = array![];
            let mut res = syscalls::call_contract_syscall(
                token, selector!("name"), call_data.span(),
            )
                .unwrap_syscall();

            let name = if res.len() == 1 {
                // Old standard (felt252)
                let name = OptionTrait::expect(
                    Serde::<felt252>::deserialize(ref res), 'Could not deserialize name',
                );
                utils::felt252_to_string(name)
            } else {
                // New standard (ByteArray)
                OptionTrait::expect(
                    Serde::<ByteArray>::deserialize(ref res), 'Could not deserialize name',
                )
            };

            let mut res = syscalls::call_contract_syscall(
                token, selector!("symbol"), call_data.span(),
            )
                .unwrap_syscall();

            let symbol = if res.len() == 1 {
                // Old standard (felt252)
                let symbol = OptionTrait::expect(
                    Serde::<felt252>::deserialize(ref res), 'Could not deserialize symbol',
                );
                utils::felt252_to_string(symbol)
            } else {
                // New standard (ByteArray)
                OptionTrait::expect(
                    Serde::<ByteArray>::deserialize(ref res), 'Could not deserialize symbol',
                )
            };

            let decimals = {
                let mut res = syscalls::call_contract_syscall(
                    token, selector!("decimals"), call_data.span(),
                )
                    .unwrap_syscall();

                let decimals = OptionTrait::expect(
                    Serde::<u8>::deserialize(ref res), 'Could not deserialize decimals',
                );
                decimals
            };

            self.emit(Event::LogMetadata(LogMetadata { address: token, name, symbol, decimals }))
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** near/omni-bridge/src/lib.rs (L316-384)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn log_metadata(&self, token_id: &AccountId) -> Promise {
        ext_token::ext(token_id.clone())
            .with_static_gas(LOG_METADATA_GAS)
            .ft_metadata()
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(LOG_METADATA_CALLBACK_GAS)
                    .with_attached_deposit(env::attached_deposit())
                    .log_metadata_callback(token_id),
            )
    }

    #[private]
    #[result_serializer(borsh)]
    pub fn log_metadata_callback(
        &self,
        #[callback] metadata: FungibleTokenMetadata,
        token_id: &AccountId,
    ) -> Promise {
        require!(
            !metadata.name.is_empty() && !metadata.symbol.is_empty(),
            BridgeError::InvalidMetadata.as_ref()
        );

        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };

        let payload = near_sdk::env::keccak256_array(
            borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_LOG_METADATA_CALLBACK_GAS)
                    .sign_log_metadata_callback(metadata_payload),
            )
    }

    #[private]
    #[result_serializer(borsh)]
    pub fn sign_log_metadata_callback(
        &self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] metadata_payload: MetadataPayload,
    ) {
        if let Ok(signature) = call_result {
            env::log_str(
                &OmniBridgeEvent::LogMetadataEvent {
                    signature,
                    metadata_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L471-480)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L715-727)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
```

**File:** near/omni-bridge/src/lib.rs (L1147-1175)
```rust
    #[private]
    pub fn deploy_token_callback(
        &mut self,
        attached_deposit: NearToken,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> Promise {
        let Ok(ProverResult::LogMetadata(metadata)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str());
        };

        let chain = metadata.emitter_address.get_chain();
        require!(
            self.factories.get(&chain) == Some(metadata.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L2397-2419)
```rust
    fn deploy_token_internal(
        &mut self,
        chain_kind: ChainKind,
        token_address: &OmniAddress,
        metadata: BasicMetadata,
        attached_deposit: NearToken,
    ) -> Promise {
        let deployer = self
            .token_deployer_accounts
            .get(&chain_kind)
            .unwrap_or_else(|| env::panic_str(BridgeError::DeployerNotSet.to_string().as_str()));
        let prefix = token_address.get_token_prefix();
        let token_id: AccountId = format!("{prefix}.{deployer}")
            .parse()
            .unwrap_or_else(|_| env::panic_str(BridgeError::ParseAccountId.to_string().as_str()));

        let storage_usage = env::storage_usage();
        self.add_token(
            &token_id,
            token_address,
            metadata.decimals,
            metadata.decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2776-2787)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }

    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
