### Title
No Validation of `recipient` String in Solana `InitTransferPayload` Causes Permanent Fund Loss — (File: `solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`, `init_transfer_sol.rs`)

---

### Summary

The Solana bridge program accepts any arbitrary string as the `recipient` field in `InitTransferPayload` without validating that it is a well-formed NEAR account ID. When a user submits an `init_transfer` with an invalid or non-existent NEAR recipient, tokens are burned or locked on Solana and an immutable Wormhole message is posted — but the NEAR side will reject the finalization because the recipient is invalid. There is no automated recovery path: burned bridged tokens are permanently lost, and locked native tokens can only be recovered through manual DAO intervention (contract upgrade).

---

### Finding Description

In `init_transfer_sol.rs`, the `process` function accepts an `InitTransferPayload` and immediately:
1. Transfers SOL into the vault (locking it)
2. Posts an immutable Wormhole message containing the unvalidated `recipient` string [1](#0-0) 

There is no check that `payload.recipient` is a syntactically valid NEAR account ID before the token state change and Wormhole post occur. The same pattern applies to the SPL-token variant in `init_transfer.rs`.

The Wormhole VAA is cryptographically signed and immutable once posted. When the NEAR side reads the VAA and attempts to finalize the transfer, it will fail to parse or resolve the recipient, causing the finalization to revert. The tokens on Solana are already burned or locked with no corresponding unlock mechanism.

The project's own `solana/SECURITY.md` explicitly acknowledges this gap: [2](#0-1) 

> "No validation of `recipient` string in `InitTransferPayload` — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed."

The classification there is "low-severity," but the PoolTogether precedent demonstrates that this vulnerability class — user-controlled parameter, no validation, no recovery — is high-severity when a UI bug or simple mistake can trigger complete loss of funds.

---

### Impact Explanation

- **Bridged tokens**: permanently and irrecoverably burned on Solana; the NEAR side never mints the corresponding amount.
- **Native tokens (SOL/SPL)**: locked in the vault with no automated unlock; recovery requires a DAO-initiated contract upgrade, which is not guaranteed and is not a user-accessible path.
- No refund or cancel mechanism exists on the Solana side once the Wormhole message is posted.
- The `InitTransfer` event/VAA is the sole data the NEAR side sees; an invalid recipient in it cannot be corrected after the fact. [3](#0-2) 

---

### Likelihood Explanation

Any unprivileged user calling `init_transfer` or `init_transfer_sol` on Solana can supply an arbitrary `recipient` string. A UI bug, copy-paste error, or simple typo in the NEAR account ID is a realistic everyday scenario. The PoolTogether judge explicitly noted that this vulnerability class qualifies as high risk because "A UI bug or simple mistake could cause complete loss of funds." No special privileges or adversarial intent are required.

---

### Recommendation

Validate the `recipient` string against NEAR account ID rules (lowercase alphanumeric, dots, underscores, hyphens; 2–64 characters; no leading/trailing dots) **before** any token state change or Wormhole post:

```rust
impl InitTransferSol<'_> {
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.fee == 0, ErrorCode::InvalidFee);
        require!(payload.amount > 0, ErrorCode::InvalidArgs);
        // ADD: validate recipient is a plausible NEAR account ID
        require!(
            is_valid_near_account_id(&payload.recipient),
            ErrorCode::InvalidArgs
        );
        // ... rest of function
    }
}
```

As defense-in-depth, add a refund/cancel path on the Solana side that can be triggered if the NEAR-side finalization proof of failure is submitted within a timeout window.

---

### Proof of Concept

1. User calls `init_transfer_sol` on Solana with `recipient = "INVALID!!account"` (or an empty string, or a 65-character string, or any string that is not a valid NEAR account ID).
2. SOL is transferred into the `sol_vault` PDA — tokens are now locked.
3. A Wormhole message is posted containing the invalid recipient string; this VAA is immutable.
4. A relayer observes the VAA and calls `fin_transfer` on the NEAR bridge.
5. The NEAR contract attempts to parse `"INVALID!!account"` as an `AccountId` — this panics or returns an error.
6. The finalization reverts; the NEAR side never mints or transfers tokens to anyone.
7. The SOL remains locked in the Solana vault with no unlock instruction available to the user.
8. No recovery function exists on either chain; the user's funds are permanently inaccessible without a DAO-level contract upgrade.

This is a direct structural analog to the PoolTogether `_startTimestamp` bug: a user-controlled parameter (`recipient` string vs. `_startTimestamp`) accepted without validation causes bridged funds to be permanently locked with no automated recovery path. [4](#0-3) [5](#0-4)

### Citations

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

**File:** solana/SECURITY.md (L13-18)
```markdown
## Known Issues

Low-severity items acknowledged but not yet addressed:

- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
- **No validation of `fee_recipient` length in `FinalizeTransferPayload`** — Excessively large strings increase Wormhole message size. Bounded by Solana tx size limits in practice.
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```
