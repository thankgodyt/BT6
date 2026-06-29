Now I have all the information needed to analyze this exploit path thoroughly. Let me verify the `MplMetadata` struct fields to confirm the `mint` field exists and is not checked.

### Title
Missing Metaplex Metadata `mint` Field Validation in `parse_metadata_account` Enables Spoofed Token Identity on NEAR — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

---

### Summary

`parse_metadata_account` verifies that the caller-supplied metadata account's **address** matches `metadata_pointer.metadata_address.0`, but never verifies that the deserialized Metaplex `Metadata` struct's **`mint` field** matches `self.mint.key()`. An attacker can create a Token-2022 mint whose `MetadataPointer` extension points to any legitimate token's Metaplex PDA (e.g., USDC's), call `log_metadata`, and cause the Wormhole VAA to carry the victim token's name/symbol paired with the attacker's mint pubkey. NEAR's `deploy_token_callback` then deploys a spoofed "USD Coin"/"USDC" NEP-141 token mapped to the attacker's mint, enabling the attacker to mint unlimited worthless tokens, bridge them to NEAR as "USDC", and sell them to users.

---

### Finding Description

The `LogMetadata` instruction handler in `process()` handles Token-2022 mints with a `MetadataPointer` extension whose `metadata_address` points to a third-party account: [1](#0-0) 

It delegates to `parse_metadata_account(metadata_pointer.metadata_address.0)`: [2](#0-1) 

The only guard is `require_keys_eq!(metadata.key(), address, ...)` — confirming the caller-supplied account is at the expected address — and `metadata.owner == &MetaplexID`. After those two checks pass, the code reads `metadata.name` and `metadata.symbol` directly, with **no check that `metadata.mint == self.mint.key()`**.

The Metaplex `Metadata` struct layout (confirmed by the test helper) contains a `mint` field at bytes 33–64: [3](#0-2) 

This field is never validated against the mint being registered.

The resulting payload unconditionally uses the attacker's mint as the token address: [4](#0-3) 

On NEAR, `deploy_token_callback` checks only that the emitter is the registered Solana factory, then calls `deploy_token_internal` with whatever name/symbol/token_address arrived in the VAA: [5](#0-4) 

`deploy_token_internal` derives the NEAR token account ID from the attacker's mint pubkey via `get_token_prefix()`, stores the `OmniAddress::Sol(attacker_mint) → token_id` mapping, and deploys a new NEP-141 token with the stolen name/symbol: [6](#0-5) 

---

### Impact Explanation

The attacker controls the `mint_authority` of their Token-2022 mint (the constraint only excludes the bridge authority PDA): [7](#0-6) 

This means the attacker can:
1. Mint unlimited attacker tokens.
2. Bridge them to NEAR via `init_transfer` → they are locked in the bridge vault and the attacker receives the spoofed "USD Coin"/"USDC" NEP-141 token on NEAR.
3. Sell the spoofed "USDC" to users who believe it is real USDC.
4. Users who bridge the spoofed "USDC" back to Solana receive the attacker's worthless Token-2022 tokens.

This is token metadata binding confusion causing direct financial loss to users — a Critical impact under the scope ("token metadata binding confusion that changes user or protocol balances").

---

### Likelihood Explanation

The attack is fully permissionless. Creating a Token-2022 mint with a custom `MetadataPointer` extension is a standard on-chain operation requiring no special roles. The attacker only needs to:
- Create a Token-2022 mint with `MetadataPointer.metadata_address = <victim_metaplex_pda>`.
- Call `log_metadata` with the victim's Metaplex PDA as the optional `metadata` account.
- Wait for the Wormhole relayer to deliver the VAA to NEAR.
- Call `deploy_token` on NEAR with the VAA.

All steps are locally reproducible on a private testnet with unmodified production code.

---

### Recommendation

In `parse_metadata_account`, after deserializing the Metaplex `Metadata` struct, add a check that the metadata's `mint` field matches the mint being registered:

```rust
if metadata.owner == &MetaplexID {
    let data = metadata.try_borrow_data()?;
    let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
    // ADD THIS:
    require_keys_eq!(
        metadata.mint,
        self.mint.key(),
        ErrorCode::InvalidTokenMetadataAddress,
    );
    Ok((metadata.name.clone(), metadata.symbol.clone()))
}
```

This ensures that a Metaplex metadata account can only be used to supply name/symbol for the exact mint it was created for, closing the cross-mint metadata theft vector.

---

### Proof of Concept

Using the existing Mollusk test harness:

1. Create a Token-2022 mint (`attacker_mint`) with `MetadataPointer.metadata_address = usdc_metaplex_pda`.
2. Build a Metaplex metadata account at `usdc_metaplex_pda` with `mint = usdc_real_mint`, `name = "USD Coin"`, `symbol = "USDC"`, owned by `MetaplexID`.
3. Call `log_metadata` with `mint = attacker_mint`, `metadata = usdc_metaplex_pda`.
4. Assert the instruction succeeds.
5. Deserialize the Wormhole message payload and assert:
   - `payload.token == attacker_mint` ✓
   - `payload.name == "USD Coin"` ✓ (stolen from USDC's metadata)
   - `payload.symbol == "USDC"` ✓ (stolen from USDC's metadata)
6. Submit the resulting VAA to NEAR `deploy_token`; assert a new NEP-141 token is deployed with `name = "USD Coin"`, `symbol = "USDC"`, mapped to `OmniAddress::Sol(attacker_mint)`.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-45)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L72-89)
```rust
    fn parse_metadata_account(&self, address: Pubkey) -> Result<(String, String)> {
        let metadata = self
            .metadata
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::TokenMetadataNotProvided))?
            .to_account_info();
        require_keys_eq!(
            metadata.key(),
            address,
            ErrorCode::InvalidTokenMetadataAddress,
        );
        if metadata.owner == &MetaplexID {
            let data = metadata.try_borrow_data()?;
            let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
            Ok((metadata.name.clone(), metadata.symbol.clone()))
        } else {
            Ok((String::default(), String::default()))
        }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L104-106)
```rust
                } else if metadata_pointer.metadata_address.0 != Pubkey::default() {
                    // Third-party metadata
                    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L130-136)
```rust
        let payload = LogMetadataPayload {
            token: self.mint.key(),
            name: name.trim_end_matches('\0').to_string(),
            symbol: symbol.trim_end_matches('\0').to_string(),
            decimals: self.mint.decimals,
        }
        .serialize_for_near(())?;
```

**File:** solana/programs/bridge_token_factory/tests/mollusk/helpers.rs (L358-374)
```rust
/// The format follows mpl-token-metadata's Metadata layout:
/// key(1) + update_authority(32) + mint(32) + data{name,symbol,uri,fee,creators}
/// + primary_sale(1) + is_mutable(1) + edition_nonce(option) + ...
pub fn create_metaplex_metadata_account(
    update_authority: &Pubkey,
    mint: &Pubkey,
    name: &str,
    symbol: &str,
) -> Account {
    let metaplex = metaplex_id();
    let mut data = Vec::with_capacity(256);
    // Key: MetadataV1 = 4
    data.push(4);
    // update_authority
    data.extend_from_slice(update_authority.as_ref());
    // mint
    data.extend_from_slice(mint.as_ref());
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

**File:** near/omni-bridge/src/lib.rs (L2397-2426)
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

        require!(
            self.deployed_tokens.insert(&token_id),
            BridgeError::TokenExists.as_ref()
        );
        self.deployed_tokens_v2
            .insert(&token_id, &token_address.get_chain());
```
