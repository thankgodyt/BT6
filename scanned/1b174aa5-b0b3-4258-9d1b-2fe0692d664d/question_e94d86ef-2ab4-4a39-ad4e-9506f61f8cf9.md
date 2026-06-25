[File: 'solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs -> Scope: Critical. Cross-chain replay, message forgery, event/proof parsing flaw, light-client verification bypass, Wormhole VAA verification bypass, or chain/domain separation flaw enabling invalid finalization or double-spending'] [Function: set_derived_near_bridge_address / verify_signature] Can an attacker exploit the absence of a bridge-instance domain separator in the secp256k1 signature scheme to replay a finalize_transfer message signed for a

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs (L1-54)
```rust
use anchor_lang::prelude::*;

use crate::{constants::CONFIG_SEED, state::config::Config};

#[derive(Accounts)]
pub struct ChangeConfig<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bumps.config,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
    )]
    pub signer: Signer<'info>,
}

impl ChangeConfig<'_> {
    pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
        self.config.admin = admin;

        Ok(())
    }

    pub fn set_pausable_admin(&mut self, pausable_admin: Pubkey) -> Result<()> {
        self.config.pausable_admin = pausable_admin;

        Ok(())
    }

    pub fn set_paused(&mut self, paused: u8) -> Result<()> {
        self.config.paused = paused;

        Ok(())
    }

    pub fn set_metadata_admin(&mut self, metadata_admin: Pubkey) -> Result<()> {
        self.config.metadata_admin = metadata_admin;

        Ok(())
    }

    pub fn set_derived_near_bridge_address(
        &mut self,
        derived_near_bridge_address: [u8; 64],
    ) -> Result<()> {
        self.config.derived_near_bridge_address = derived_near_bridge_address;

        Ok(())
    }
}
```

**File:** solana/programs/bridge_token_factory/src/state/config.rs (L18-29)
```rust
#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub max_used_nonce: u64,
    pub derived_near_bridge_address: [u8; 64],
    pub bumps: ConfigBumps,
    pub paused: u8,
    pub pausable_admin: Pubkey,
    pub metadata_admin: Pubkey,
    pub padding: [u8; 35],
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L23-47)
```rust
impl<P: Payload> SignedPayload<P> {
    pub fn verify_signature(
        &self,
        params: P::AdditionalParams,
        derived_near_bridge_address: &[u8; 64],
    ) -> Result<()> {
        let serialized = self.payload.serialize_for_near(params)?;
        let hash = keccak::hash(&serialized);

        let signature_bytes = &self.signature[0..64];

        let signature = libsecp256k1::Signature::parse_standard_slice(signature_bytes)
            .map_err(|_| ProgramError::InvalidArgument)?;
        require!(!signature.s.is_high(), ErrorCode::MalleableSignature);

        let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
            .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;

        require!(
            signer.0 == *derived_near_bridge_address,
            ErrorCode::SignatureVerificationFailed
        );

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L18-44)
```rust
impl Payload for FinalizeTransferPayload {
    type AdditionalParams = (Pubkey, Pubkey); // mint, recipient
    fn serialize_for_near(&self, params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        // 0. prefix
        IncomingMessageType::InitTransfer.serialize(&mut writer)?;
        // 1. destination_nonce
        self.destination_nonce.serialize(&mut writer)?;
        // 2. transfer_id
        writer.write_all(&[self.transfer_id.origin_chain])?;
        self.transfer_id.origin_nonce.serialize(&mut writer)?;
        // 3. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
        // 6. fee_recipient
        self.fee_recipient.serialize(&mut writer)?;

        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
}
```

**File:** solana/programs/bridge_token_factory/src/state/used_nonces.rs (L39-112)
```rust
    pub fn use_nonce<'info>(
        nonce: u64,
        loader: &AccountLoader<'info, Self>,
        config: &mut Account<'info, Config>,
        rent_reserve: AccountInfo<'info>,
        payer: AccountInfo<'info>,
        rent: &Rent,
        system_program: AccountInfo<'info>,
    ) -> Result<()> {
        if config.max_used_nonce < nonce {
            config.max_used_nonce = nonce;
        }
        // use max_used_nonce instead of the requested one to ignore the usage of the nonces from the gap
        let expected_rent_reserve_lamports =
            rent.minimum_balance(0) + Self::rent_level(config.max_used_nonce, rent)?;
        let current_rent_reserve_lamports = rent_reserve.lamports();
        if current_rent_reserve_lamports < expected_rent_reserve_lamports {
            // pay for the rent of the next account
            transfer(
                CpiContext::new(
                    system_program,
                    Transfer {
                        from: payer,
                        to: rent_reserve,
                    },
                ),
                expected_rent_reserve_lamports - current_rent_reserve_lamports,
            )?;
        } else {
            // compensate for the account creation
            let compensation = current_rent_reserve_lamports - expected_rent_reserve_lamports;
            if compensation > 0 {
                // compensate expenses for the account creation
                transfer(
                    CpiContext::new_with_signer(
                        system_program,
                        Transfer {
                            from: rent_reserve,
                            to: payer,
                        },
                        &[&[AUTHORITY_SEED, &[config.bumps.authority]]],
                    ),
                    compensation,
                )?;
            }
        }
        #[cfg(not(feature =
