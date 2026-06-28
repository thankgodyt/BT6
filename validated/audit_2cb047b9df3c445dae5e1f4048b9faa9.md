### Title
Native SOL Fee Payments Permanently Locked in `sol_vault` with No Withdrawal Mechanism — (File: `solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

When a user initiates an SPL-token bridge transfer via `init_transfer` and specifies a non-zero `native_fee`, that SOL is deposited into the `sol_vault` PDA. No instruction in the program allows anyone — admin, relayer, or protocol — to withdraw these accumulated fee lamports. They are permanently locked.

---

### Finding Description

The `bridge_token_factory` Solana program has two transfer-initiation paths:

1. **`init_transfer`** — bridges SPL tokens. If `payload.native_fee > 0`, the user's SOL is transferred to `sol_vault`: [1](#0-0) 

2. **`init_transfer_sol`** — bridges native SOL. Both `amount` and `native_fee` go to `sol_vault`: [2](#0-1) 

The `sol_vault` PDA (seed `b"sol_vault"`) is documented as serving two purposes: holding bridged SOL for cross-chain transfers and holding rent reserves for nonce accounts. [3](#0-2) 

The only instruction that withdraws from `sol_vault` is `finalize_transfer_sol`, which transfers exactly `data.amount` to the recipient — the bridged SOL principal only: [4](#0-3) 

The `native_fee` component deposited by `init_transfer` (SPL path) is **never withdrawn** by any instruction. The complete set of admin instructions is `change_config`, `initialize`, `pause`, and `update_metadata` — none of which touch `sol_vault`:



The complete set of user instructions contains no `withdraw_fees` or equivalent:



On the NEAR side, the relayer is compensated for the `native_fee` by having wrapped SOL minted to them via `send_fee_internal`. The actual SOL deposited into `sol_vault` on Solana is never claimed. [5](#0-4) 

---

### Impact Explanation

Every `init_transfer` call with `native_fee > 0` permanently locks that SOL in `sol_vault`. Over the lifetime of the bridge, all SOL fee payments from SPL-token transfers accumulate in `sol_vault` with no recovery path. This constitutes permanent freezing of fee funds that belong to the relayer/protocol. The `sol_vault` balance grows unboundedly beyond what is needed to service `finalize_transfer_sol` withdrawals, and the excess is irrecoverable without a program upgrade.

---

### Likelihood Explanation

Every user who pays a `native_fee` when bridging SPL tokens triggers this condition. The bridge is designed to incentivize relayers with fees, and the NEAR-side documentation and tests confirm `native_fee` is a standard, expected payment path. This is not an edge case — it is the normal operating mode for any transfer where the user pays a SOL-denominated relayer fee. [6](#0-5) 

---

### Recommendation

Add an admin-gated `withdraw_fees` instruction that transfers the excess lamports from `sol_vault` (i.e., `sol_vault.lamports() - rent_exempt_minimum`) to a designated fee recipient. This mirrors the fix described in the external report: add a withdrawal instruction so that accumulated fee payments can be claimed by the authorized party.

---

### Proof of Concept

1. User calls `init_transfer` with `amount = 1_000_000`, `fee = 100`, `native_fee = 5_000_000` (5 mSOL).
2. `init_transfer.process()` transfers 5_000_000 lamports from the user to `sol_vault`.
3. The Wormhole VAA is picked up by the NEAR relayer, who calls `fin_transfer` and then `claim_fee` on NEAR. The NEAR bridge mints wrapped SOL to the relayer as the `native_fee` reward.
4. The 5_000_000 lamports remain in `sol_vault` on Solana indefinitely.
5. Repeat for every SPL-token bridge transfer with a non-zero `native_fee`. The `sol_vault` balance grows monotonically. No instruction exists to recover these lamports. [1](#0-0) [4](#0-3)

### Citations

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

**File:** solana/CLAUDE.md (L22-22)
```markdown
| `b"sol_vault"` | Holds native SOL for cross-chain transfers + rent reserve for nonce accounts |
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

**File:** near/omni-bridge/src/lib.rs (L2656-2673)
```rust
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```
