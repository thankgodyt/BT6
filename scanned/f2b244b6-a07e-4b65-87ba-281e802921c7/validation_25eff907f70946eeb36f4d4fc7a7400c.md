### Title
Unvalidated `recipient` String in Solana `InitTransferPayload` Causes Permanent Loss of Bridged Funds — (`solana/programs/bridge_token_factory/src/state/message/init_transfer.rs`)

---

### Summary

The Solana bridge program accepts any arbitrary string as the `recipient` field in `InitTransferPayload` without format validation. When a user provides an invalid recipient address, tokens are burned or locked on Solana and a Wormhole VAA is posted, but the NEAR-side `fin_transfer` fails to parse the recipient and panics. There is no cancel or refund mechanism on the Solana side, so the bridged funds are permanently lost or frozen.

---

### Finding Description

In `solana/programs/bridge_token_factory/src/state/message/init_transfer.rs`, the `InitTransferPayload` struct defines `recipient` as a plain `String` with no format constraints:

```rust
pub struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,   // ← no validation whatsoever
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
}
``` [1](#0-0) 

The `process()` handler in `init_transfer.rs` only checks `amount > fee` and token mint authority; it never inspects `recipient`:

```rust
pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
    require!(payload.amount > payload.fee, ErrorCode::InvalidFee);
    // ... vault lock or burn — no recipient check
    self.common.post_message(payload.serialize_for_near(...))?;
    Ok(())
}
``` [2](#0-1) 

The same absence of validation applies to `init_transfer_sol`: [3](#0-2) 

The raw string is serialized directly into the Wormhole message payload:

```rust
// 7. recipient
self.recipient.serialize(&mut writer)?;
``` [4](#0-3) 

On the NEAR side, the Wormhole prover proxy attempts to parse the recipient string via `OmniAddress::from_str`:

```rust
recipient: transfer.recipient.parse().map_err(stringify)?,
``` [5](#0-4) 

`OmniAddress::from_str` rejects strings that do not match a valid `chain:address` format. For example, `"invalid_address"` (no colon) defaults to ETH parsing and fails; `"near:invalid account!!!"` fails NEAR account ID validation: [6](#0-5) 

When the prover returns an error, `fin_transfer_callback` panics:

```rust
let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
    env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
};
``` [7](#0-6) 

The Solana program has no cancel-transfer or refund instruction. Once tokens are burned or locked and the VAA is posted, there is no on-chain path to recover them if the NEAR side always rejects the VAA.

This is explicitly acknowledged in the repository's own security notes:

> **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed. [8](#0-7) 

The protocol team classifies this as "low-severity," but the actual impact is permanent fund loss for burned bridged tokens, which is critical.

---

### Impact Explanation

When a user provides an invalid `recipient` string:

1. Tokens are **burned** (bridged tokens) or **locked** (native tokens) on Solana — irreversible on the Solana side.
2. The Wormhole VAA is posted and cannot be cancelled.
3. The NEAR-side `fin_transfer` always panics for this VAA because recipient parsing fails.
4. There is no cancel/refund instruction in the Solana program.
5. For burned bridged tokens: **permanent loss** — tokens no longer exist on Solana and NEAR never mints the destination-side equivalent.
6. For locked native tokens: **permanent freeze** — tokens are stuck in the vault with no on-chain recovery path short of a protocol-level admin action.

This matches the critical impact scope: *permanent freezing or loss of bridged funds across Solana or Wormhole-routed flows*.

---

### Likelihood Explanation

Any unprivileged user calling `init_transfer` or `init_transfer_sol` on Solana can trigger this by supplying an invalid `recipient` string. The Solana program provides no pre-flight validation or error feedback before tokens are committed. The scenario is reachable through:

- **User error**: a user misformats the recipient address (e.g., omits the chain prefix, uses an invalid NEAR account ID, or provides a hex string without the `0x` prefix for an EVM address).
- **Intentional self-harm / griefing**: an attacker deliberately burns their own tokens to create an unresolvable VAA, consuming relayer resources and polluting the bridge state.

No admin compromise, MPC collusion, or external dependency failure is required.

---

### Recommendation

Validate the `recipient` string in `InitTransferPayload::process()` **before** locking or burning tokens. The simplest approach is to attempt to deserialize it using the same `OmniAddress` parsing logic used on the NEAR side, and reject the instruction with a clear error if parsing fails. This ensures that only recipient strings that the NEAR bridge can successfully process are accepted, preventing the irreversible token commitment.

---

### Proof of Concept

1. Call `init_transfer` on Solana with `payload.recipient = "near:invalid account!!!"` (or any string that fails `OmniAddress::from_str`).
2. Observe that tokens are burned/locked on Solana and a Wormhole VAA is posted — the Solana instruction succeeds.
3. Relayer submits the VAA to NEAR's `fin_transfer`.
4. The Wormhole prover proxy calls `transfer.recipient.parse()`, which returns `Err` for the malformed string.
5. `fin_transfer_callback` panics with `ERR_INVALID_PROOF_MESSAGE`.
6. The VAA cannot be resubmitted successfully (the recipient is always invalid).
7. Tokens on Solana are permanently unrecoverable without out-of-band admin intervention.

### Citations

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L7-14)
```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L37-39)
```rust
        // 7. recipient
        self.recipient.serialize(&mut writer)?;
        // 8. message
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L72-130)
```rust
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.amount > payload.fee, ErrorCode::InvalidFee);

        if payload.native_fee > 0 {
            transfer(
                CpiContext::new(
                    self.common.system_program.to_account_info(),
                    Transfer {
                        from: self.user.to_account_info(),
                        to: self.sol_vault.to_account_info(),
                    },
                ),
                payload.native_fee,
            )?;
        }

        if let Some(vault) = &self.vault {
            // Native version. We have a proof of token registration by vault existence
            transfer_checked(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    TransferChecked {
                        from: self.from.to_account_info(),
                        to: vault.to_account_info(),
                        authority: self.user.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
                self.mint.decimals,
            )?;
        } else {
            // Bridged version. May be a fake token with our authority set but it will be ignored on the near side
            require!(
                self.mint.mint_authority.contains(self.authority.key),
                ErrorCode::InvalidBridgedToken
            );

            burn(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    Burn {
                        mint: self.mint.to_account_info(),
                        from: self.from.to_account_info(),
                        authority: self.user.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
            )?;
        }

        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs (L35-62)
```rust
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.fee == 0, ErrorCode::InvalidFee);
        require!(payload.amount > 0, ErrorCode::InvalidArgs);

        transfer(
            CpiContext::new(
                self.common.system_program.to_account_info(),
                Transfer {
                    from: self.user.to_account_info(),
                    to: self.sol_vault.to_account_info(),
                },
            ),
            payload
                .native_fee
                .checked_add(
                    payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
                )
                .ok_or_else(|| error!(ErrorCode::InvalidArgs))?,
        )?;

        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            Pubkey::default(),
        ))?)?;

        Ok(())
    }
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L173-174)
```rust
            recipient: transfer.recipient.parse().map_err(stringify)?,
            origin_nonce: transfer.origin_nonce,
```

**File:** near/omni-types/src/lib.rs (L392-411)
```rust
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L705-707)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
