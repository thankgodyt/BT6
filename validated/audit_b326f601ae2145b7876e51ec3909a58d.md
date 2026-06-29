Audit Report

## Title
Token-2022 MetadataPointer Cross-Mint Metadata Spoofing in `parse_metadata_account` — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

## Summary
`parse_metadata_account` verifies that the supplied Metaplex account's pubkey matches the address stored in the Token-2022 `MetadataPointer` extension and that the account is owned by the Metaplex program, but never checks that the Metaplex account's embedded `mint` field matches `self.mint.key()`. An attacker can create a Token-2022 mint whose `MetadataPointer` points to the Metaplex PDA of any legitimate token (e.g., USDC), pass that legitimate Metaplex account as the optional `metadata` argument, and cause the emitted Wormhole VAA to carry the attacker's mint pubkey as `token_address` but the legitimate token's `name`/`symbol`/`decimals`. NEAR's `deploy_token_callback` then deploys a bridged NEP-141 token with spoofed identity, enabling a fake "USDC"-named NEAR token backed by a worthless mint.

## Finding Description
In `parse_metadata_account` (lines 72–90 of `log_metadata.rs`), two checks are performed:

1. **Key equality** (lines 78–82): `require_keys_eq!(metadata.key(), address, ...)` — ensures the passed account's pubkey equals the address from the `MetadataPointer` extension.
2. **Owner equality** (line 83): `metadata.owner == &MetaplexID` — ensures the account is owned by Metaplex.

The function then deserializes and returns `metadata.name` and `metadata.symbol` (line 86) **without ever verifying** `metadata.mint == self.mint.key()`.

In `process()`, when `token_program == token_2022::ID` and the `MetadataPointer` extension's `metadata_address` is neither the mint itself nor `Pubkey::default()`, the code unconditionally calls `parse_metadata_account` with the attacker-controlled pointer value (lines 104–106). The Token-2022 program imposes no constraint that the pointed-to Metaplex account belongs to the same mint — the `MetadataPointer` extension is set freely by the mint creator at mint-creation time.

After `parse_metadata_account` returns the legitimate token's name/symbol, the payload is assembled with the **attacker's mint pubkey** as `token` but the legitimate token's strings as `name`/`symbol` (lines 130–136). On the NEAR side, `deploy_token_callback` (lines 1155–1174 of `near/omni-bridge/src/lib.rs`) trusts the VAA payload entirely, passing `metadata.token_address` (attacker's mint M) and `metadata.name`/`metadata.symbol` (USDC's strings) directly to `deploy_token_internal`. `deploy_token_internal` derives the NEAR token account ID from the token address prefix (lines 2408–2411) and deploys a new NEP-141 token with the spoofed name/symbol.

The only constraint on the mint account (line 42: `!mint.mint_authority.contains(authority.key)`) merely requires that the bridge authority is not the mint authority — trivially satisfied for any attacker-created mint.

## Impact Explanation
This is a concrete instance of **token metadata binding confusion** within the Critical allowed scope. An attacker deploys a worthless Token-2022 mint M and causes the bridge to register a NEAR token with USDC's name and symbol but keyed to M's address. Users who bridge M tokens lock worthless tokens on Solana and receive a NEAR token that is visually indistinguishable from the legitimate bridged USDC. Any user who accepts this fake token as payment or trades it on a DEX suffers permanent loss of funds. The spoofed token is permanently registered in the bridge's state under M's address with USDC's display metadata.

## Likelihood Explanation
The attack is fully permissionless. Creating a Token-2022 mint with an arbitrary `MetadataPointer` requires no special privileges, no admin access, and no oracle manipulation. The legitimate Metaplex account for USDC (or any other high-value token) is a public on-chain account that any caller can pass as the optional `metadata` argument. The only cost is the SOL rent for the new mint and vault accounts. The attack is locally reproducible on an unmodified codebase and repeatable for any token whose Metaplex PDA exists on-chain.

## Recommendation
After deserializing the Metaplex account in `parse_metadata_account`, add a check that the account's embedded `mint` field matches the mint being logged:

```rust
if metadata.owner == &MetaplexID {
    let data = metadata.try_borrow_data()?;
    let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
    // ADD THIS CHECK:
    require_keys_eq!(
        metadata.mint,
        self.mint.key(),
        ErrorCode::InvalidTokenMetadataAddress,
    );
    Ok((metadata.name.clone(), metadata.symbol.clone()))
} else {
    Ok((String::default(), String::default()))
}
```

This ensures that even if an attacker's mint points to a legitimate token's Metaplex PDA, the deserialized metadata's `mint` field will not match the attacker's mint pubkey, causing the transaction to fail.

## Proof of Concept
```
// localnet / mollusk test outline
//
// 1. Let U = USDC mint pubkey (classic SPL Token)
//    Let U_meta = find_program_address(
//        [METADATA_SEED, MetaplexID, U], MetaplexID
//    )
//    (U_meta is owned by MetaplexID, contains name="USD Coin", symbol="USDC", mint=U)
//
// 2. Create Token-2022 mint M with:
//      MetadataPointer { metadata_address: U_meta }
//    M's mint_authority = attacker (not bridge authority → passes constraint)
//
// 3. Call log_metadata(mint=M, metadata=U_meta_account)
//
// 4. Inside process():
//      token_program == token_2022::ID                           → true
//      metadata_pointer.metadata_address.0 == M.key()           → false
//      metadata_pointer.metadata_address.0 != Pubkey::default() → true
//      → calls parse_metadata_account(U_meta)
//
// 5. Inside parse_metadata_account(address=U_meta):
//      metadata.key() == U_meta                                  → PASS
//      metadata.owner == MetaplexID                              → PASS
//      metadata.mint == U  (NOT checked against M)
//      → returns ("USD Coin", "USDC")
//
// 6. LogMetadataPayload { token: M, name: "USD Coin", symbol: "USDC",
//      decimals: M.decimals } is posted as a Wormhole VAA.
//
// 7. Submit VAA to NEAR deploy_token → deploys NEAR token with
//      token_address = Solana:M, name = "USD Coin", symbol = "USDC"
//
// 8. init_transfer with M locks M-tokens on Solana;
//    NEAR mints "USD Coin (USDC)"-named tokens to recipient.
//    Recipient holds a token visually identical to bridged USDC
//    but redeemable only for worthless M tokens.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L72-90)
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

**File:** near/omni-bridge/src/lib.rs (L1155-1174)
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
```

**File:** near/omni-bridge/src/lib.rs (L2408-2411)
```rust
        let prefix = token_address.get_token_prefix();
        let token_id: AccountId = format!("{prefix}.{deployer}")
            .parse()
            .unwrap_or_else(|_| env::panic_str(BridgeError::ParseAccountId.to_string().as_str()));
```
