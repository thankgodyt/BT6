Audit Report

## Title
Missing `token::authority` Constraint Allows Delegate to Drain Any Approved Token Account via `InitTransfer` - (File: `solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary
The `InitTransfer` Anchor account struct constrains `from` only by mint and token-program, omitting `token::authority = user`. Because the SPL token program permits approved delegates to act as transfer authority, any attacker holding a delegate approval on a victim's token account can call `init_transfer`, drain the victim's tokens into the bridge vault, and route them to an attacker-controlled cross-chain address. The victim suffers a complete, irreversible loss of funds.

## Finding Description
In `init_transfer.rs` lines 34–39, the `from` account is declared with only two constraints:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

There is no `token::authority = user` constraint, so Anchor never verifies that `user` owns `from`. The `user` field (lines 60–64) is only required to be a `Signer` owned by the system program — it need not be the owner of `from`.

At lines 90–102, the native-token path calls `transfer_checked` with `authority: self.user.to_account_info()`. The SPL token program accepts this call when `user` is either the token account owner **or** an approved delegate with sufficient allowance. Because Anchor imposes no ownership check, an attacker who is a delegate on the victim's account satisfies this condition.

At lines 110–120, the bridged-token path calls `burn` with the same `authority: self.user.to_account_info()`, which the SPL token program equally accepts from a delegate.

At lines 123–127, `post_message` records `self.user.key()` as the sender and the attacker-supplied `payload.recipient` as the destination, so the cross-chain message is fully attacker-controlled.

No other guard in the instruction checks the relationship between `from` and `user`. The `solana/SECURITY.md` known-issues list does not acknowledge this flaw.

## Impact Explanation
An attacker with a delegate approval on a victim's token account can call `init_transfer` to lock the victim's tokens in the bridge vault (native path) or burn them (bridged path) and emit a valid Wormhole cross-chain transfer message crediting an attacker-controlled address on NEAR, EVM, or any other supported chain. The transfer is irreversible once the Wormhole message is finalized. This is a direct, concrete theft of bridged funds, matching the critical impact class: *Stealing, loss, or permanent freezing of bridged funds across NEAR, EVM, Solana, or Wormhole-routed flows.*

## Likelihood Explanation
Solana token delegation (`spl_token::approve`) is a standard, widely-used primitive in DeFi — DEXes, lending protocols, and yield aggregators routinely request delegate approvals. A victim need not interact with the bridge at all; any prior approval of a third-party keypair or program on a bridge-supported token account is sufficient. The attacker requires no privileged role, no admin access, and no leaked keys — only a valid, unexpired delegate approval. The attack is repeatable for every victim account on which the attacker holds delegation.

## Recommendation
Add `token::authority = user` to the `from` account constraint in the `InitTransfer` struct:

```rust
#[account(
    mut,
    token::mint = mint,
    token::authority = user,          // ← add this
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

This Anchor constraint enforces `from.owner == user.key()` at account-validation time, before any CPI is executed, ensuring only the actual owner of the token account can initiate a bridge transfer.

## Proof of Concept
1. Alice holds 10,000 USDC in `alice_ata` and has previously called `spl_token::approve(alice_ata, delegate=bob, amount=10_000)` for an unrelated DeFi protocol.
2. Bob constructs an `InitTransfer` transaction:
   - `from = alice_ata`
   - `user = bob` (Bob signs)
   - `vault` = the bridge vault for USDC (native path)
   - `payload.amount = 10_000`
   - `payload.recipient = "eth:0xBob..."`
3. Anchor account validation passes: `from` satisfies `token::mint = mint` and `token::token_program = token_program`; `user` is a valid `Signer`.
4. `transfer_checked` CPI executes: SPL token program accepts Bob as a valid delegate authority for `alice_ata` → 10,000 USDC move to the bridge vault.
5. `post_message` emits a Wormhole VAA recording Bob's EVM address as recipient.
6. Wormhole guardians sign the VAA; the EVM bridge releases 10,000 USDC to Bob's address.
7. Alice's funds are permanently lost with no recourse.

A local integration test can reproduce this by: (a) minting tokens to `alice_ata`, (b) calling `spl_token::approve` to grant Bob delegate rights, (c) invoking `init_transfer` signed by Bob with `from = alice_ata`, and (d) asserting that `alice_ata` balance decreases and the vault balance increases without Alice signing.