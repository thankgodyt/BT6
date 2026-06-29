Based on my code review, this is a valid vulnerability. Here is the analysis:

---

### Title
Native Fee Lamports Permanently Locked in `sol_vault` — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs`)

### Summary
`init_transfer_sol` deposits `amount + native_fee` lamports into `sol_vault`, but `finalize_transfer_sol` only releases `data.amount` lamports to the recipient. There is no on-chain instruction to withdraw the `native_fee` portion from `sol_vault`, causing those lamports to be permanently frozen.

### Finding Description

In `init_transfer_sol::process`, the full `amount + native_fee` is transferred to `sol_vault`: [1](#0-0) 

The `native_fee` is serialized into the Wormhole message sent to NEAR: [2](#0-1) 

On the NEAR side, the relayer is compensated in NEAR-denominated tokens. When NEAR calls back to Solana via `finalize_transfer_sol`, the payload contains only `data.amount` (the bridged amount), and only that is released: [3](#0-2) 

The `native_fee` lamports remain in `sol_vault` indefinitely. The admin instruction set contains only `change_config`, `initialize`, `pause`, and `update_metadata` — none of which drain `sol_vault`:



Additionally, `init_transfer_sol` enforces `payload.fee == 0`, meaning the only fee mechanism for SOL transfers is `native_fee`, which is the exact value that gets permanently locked: [4](#0-3) 

The same pattern exists for SPL token transfers via `init_transfer`, which also deposits `native_fee` into `sol_vault` with no release path: [5](#0-4) 

### Impact Explanation
Every transfer that includes a non-zero `native_fee` permanently locks that many lamports in `sol_vault`. Over time, this accumulates into an irrecoverable pool of SOL. Users pay real SOL that is never returned to them, to the relayer, or to any protocol treasury. This constitutes permanent freezing of user-deposited bridged funds.

### Likelihood Explanation
Any user initiating a cross-chain transfer with `native_fee > 0` triggers this. Relayers typically require a `native_fee` to cover gas costs, so this is the normal production path, not an edge case.

### Recommendation
The `FinalizeTransferPayload` (sent from NEAR back to Solana) should include the `native_fee` amount and the relayer's Solana address. `finalize_transfer_sol` should then transfer `native_fee` lamports from `sol_vault` to the relayer's account in addition to transferring `data.amount` to the recipient. Alternatively, an admin-controlled withdrawal instruction for `sol_vault` should be added as a minimum safeguard.

### Proof of Concept
1. Call `init_transfer_sol` with `amount = 1_000_000` lamports and `native_fee = 10_000` lamports.
2. `sol_vault` receives `1_010_000` lamports.
3. NEAR processes the transfer; relayer receives NEAR-denominated compensation.
4. NEAR sends `FinalizeTransferPayload` with `amount = 1_000_000` back to Solana.
5. Call `finalize_transfer_sol`; recipient receives `1_000_000` lamports.
6. Assert `sol_vault` balance decreased by exactly `1_010_000` — it will have decreased by only `1_000_000`, proving `10_000` lamports are permanently locked.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs (L36-36)
```rust
        require!(payload.fee == 0, ErrorCode::InvalidFee);
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs (L39-53)
```rust
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
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L35-36)
```rust
        // 6. native_fee
        u128::from(self.native_fee).serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer_sol.rs (L79-89)
```rust
        transfer(
            CpiContext::new_with_signer(
                self.common.system_program.to_account_info(),
                Transfer {
                    from: self.sol_vault.to_account_info(),
                    to: self.recipient.to_account_info(),
                },
                &[&[SOL_VAULT_SEED, &[self.config.bumps.sol_vault]]],
            ),
            data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
        )?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L75-86)
```rust
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
```
