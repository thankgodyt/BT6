Audit Report

## Title
Untrusted `decimals()` / `ft_metadata()` Return Value Permanently Corrupts NEAR Normalization Factor — (`near/omni-bridge/src/lib.rs`, `evm/src/omni-bridge/contracts/OmniBridge.sol`, `starknet/src/omni_bridge.cairo`)

## Summary
The `log_metadata` / `logMetadata` entry points on NEAR, EVM, and Starknet are permissionless and accept an arbitrary caller-supplied token address. The `decimals` value returned by the external token contract is consumed without validation and, via the `deploy_token` / `bind_token` flows, is permanently written into NEAR's `token_decimals` storage map. Every subsequent `normalize_amount` and `denormalize_amount` call for that token uses the stored value, so a token whose `decimals()` / `ft_metadata().decimals` returns a value that differs from its actual balance precision causes all future cross-chain transfers to carry wrong amounts, resulting in permanent, irreversible fund loss for every user who bridges the affected token.

## Finding Description

**Permissionless entry points — no access control on the caller or the token argument:**

- NEAR `log_metadata` (line 316) carries only `#[pause(except(roles(Role::DAO)))]`; any external account can call it with any `token_id`. [1](#0-0) 
- EVM `logMetadata` (line 224) is `external payable` with no further restriction; any caller may supply any `tokenAddress`. [2](#0-1) 
- Starknet `log_metadata` (line 144) has no access control at all. [3](#0-2) 

**Unvalidated decimals flow into permanent storage:**

`deploy_token_callback` verifies only that the event emitter is the registered factory (i.e., the bridge contract itself), which is always true when `logMetadata` is called on the EVM bridge. It then passes `metadata.decimals` verbatim to `deploy_token_internal`. [4](#0-3) 

`deploy_token_internal` calls `add_token` with `metadata.decimals` for both `decimals` and `origin_decimals`, then inserts into `deployed_tokens`. The `deployed_tokens.insert` check prevents re-registration of the same token but does not prevent initial registration with a wrong decimal value. [5](#0-4) 

`bind_token_callback` (NEAR path) similarly calls `add_token` with `deploy_token.decimals` and `deploy_token.origin_decimals` sourced from the EVM `DeployToken` event, which itself was derived from the MPC-signed `MetadataPayload` that originated from the attacker-controlled NEAR token's `ft_metadata()`. [6](#0-5) 

**Normalization uses the stored value for every transfer:**

`sign_transfer` reads `token_decimals` and calls `normalize_amount`. [7](#0-6) 

`fin_transfer_callback` reads `token_decimals` and calls `denormalize_amount`. [8](#0-7) 

Both functions compute `diff_decimals = origin_decimals - decimals` and scale by `10^diff_decimals`. [9](#0-8) 

**Damaging exploit path (NEAR → EVM):**

1. Attacker deploys a NEAR NEP-141 token whose `ft_metadata()` returns `decimals: 24` while actual balances are denominated in 18-decimal units.
2. Attacker calls NEAR `log_metadata(malicious.near)`. The callback builds `MetadataPayload { decimals: 24 }` and requests an MPC signature.
3. The signed payload is submitted to EVM `deployToken`. EVM normalizes: token deployed with 18 decimals; `DeployToken` event carries `decimals=18, originDecimals=24`.
4. NEAR `bind_token_callback` stores `{decimals: 18, origin_decimals: 24}` in `token_decimals`.
5. A victim holds 1 unit of the NEAR token (10^18 raw units, true 18-decimal precision) and bridges to EVM. `normalize_amount(10^18, {18, 24})` computes `diff=6`, returns `10^18 / 10^6 = 10^12`. The EVM recipient receives `10^12` units of an 18-decimal token = **0.000001 EVM tokens** — a **99.9999% loss** with no recourse.

**Why existing checks are insufficient:**

- The `factories` check in `deploy_token_callback` and `bind_token_callback` only verifies the event emitter is the registered bridge/factory contract, not that the token's metadata is accurate. [10](#0-9) 
- The `deployed_tokens.insert` guard prevents duplicate registration but does nothing to validate the decimal value on first registration. [11](#0-10) 
- There is no range check, cross-check, or governance step on the `decimals` value at any point in the pipeline.

## Impact Explanation

This is a **Critical** impact matching "decimal/normalization abuse" and "token metadata binding confusion that changes user or protocol balances." Once the wrong `origin_decimals` is stored, every transfer of the affected token is scaled by the wrong power of ten. In the NEAR→EVM direction with `origin_decimals=24` and true precision 18, users lose 99.9999% of their bridged value. The stored value cannot be corrected by any unprivileged actor, making the loss permanent for all future users of that token on the bridge.

## Likelihood Explanation

The entry path is fully permissionless. Deploying a NEAR NEP-141 token (or an EVM/Starknet ERC-20) is a standard, permissionless operation. No admin action, no private key compromise, no oracle manipulation, and no threshold-signature compromise is required. The attacker only needs to deploy a token contract with a chosen `decimals` / `ft_metadata().decimals` return value and call the public `log_metadata` function. The attack is repeatable for any new token address and is irreversible once executed.

## Recommendation

1. **Validate decimals at registration time.** Assert that the returned value falls within a sane range (e.g., 1–24) before writing to storage.
2. **Guard against first-write with wrong value.** Add an explicit check that `token_decimals` is not already set before writing, and consider a two-step commit/confirm flow that allows a governance actor to reject a registration within a time window.
3. **Require an allowlist or governance approval** before a new token's normalization factor is accepted, analogous to the `factories` allowlist already used for emitter addresses.
4. **Emit the stored value, not the raw external value**, so off-chain monitors can detect discrepancies between the emitted decimals and the on-chain token's current `decimals()`.

## Proof of Concept

**NEAR → EVM path (most damaging):**

```
1. Deploy NEAR NEP-141 token `malicious.near` with ft_metadata() returning decimals=24.
   (Actual balances use 18-decimal precision.)

2. Call: near call omni-bridge.near log_metadata '{"token_id":"malicious.near"}' --deposit 1

3. MPC signs MetadataPayload{decimals:24}. Signed payload broadcast to EVM.

4. Call EVM OmniBridge.deployToken(signedPayload):
   - EVM normalizes: token deployed with 18 decimals.
   - Emits DeployToken(token="malicious.near", decimals=18, originDecimals=24).

5. Relayer submits DeployToken proof to NEAR bind_token.
   bind_token_callback stores: token_decimals["malicious.near"] = {decimals:18, origin_decimals:24}.

6. Victim holds 1 malicious.near token (10^18 raw units).
   Calls ft_transfer_call to bridge to EVM.
   normalize_amount(10^18, {18, 24}) = 10^18 / 10^6 = 10^12.
   EVM recipient receives 10^12 units of 18-decimal token = 0.000001 EVM tokens.
   Victim loses 99.9999% of bridged value. Loss is permanent.
```

**Verification:** A local integration test can deploy a mock NEP-141 token returning `decimals=24`, invoke `log_metadata`, simulate the MPC signing and EVM `deployToken` event, call `bind_token` with the resulting proof, and assert that `normalize_amount(10^18, token_decimals["malicious.near"])` returns `10^12` instead of `10^18`.

### Citations

**File:** near/omni-bridge/src/lib.rs (L316-327)
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

**File:** near/omni-bridge/src/lib.rs (L1155-1175)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1262-1267)
```rust
        self.add_token(
            &deploy_token.token,
            &deploy_token.token_address,
            deploy_token.decimals,
            deploy_token.origin_decimals,
        );
```

**File:** near/omni-bridge/src/lib.rs (L2413-2424)
```rust
        let storage_usage = env::storage_usage();
        self.add_token(
            &token_id,
            token_address,
            metadata.decimals,
            metadata.decimals,
        );

        require!(
            self.deployed_tokens.insert(&token_id),
            BridgeError::TokenExists.as_ref()
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
