### Title
`claim_fee()` Wrongly Restricts Fee Claiming to Trusted Relayers - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `claim_fee()` function in the NEAR `omni-bridge` contract carries a `#[trusted_relayer]` access guard that is redundant and overly restrictive. The function's own callback already enforces that the caller must be the fee recipient (proven by an on-chain proof). The extra relayer restriction prevents any non-relayer fee recipient from ever claiming their earned fees, permanently locking those funds.

### Finding Description

`claim_fee` is decorated with `#[trusted_relayer]`, which requires the caller to be a registered trusted relayer (or hold `Role::DAO` / `Role::UnrestrictedRelayer`): [1](#0-0) 

Inside `claim_fee_callback`, the contract already performs the correct authorization check — the caller must equal the `fee_recipient` embedded in the proof: [2](#0-1) 

The `fee_recipient` field is set by the trusted relayer when calling `sign_transfer`, and it is an arbitrary `Option<AccountId>`: [3](#0-2) 

A relayer can legitimately designate any account as the fee recipient — for example, a DAO treasury, a fee-splitting contract, or a dedicated collector account. If that account is not itself a trusted relayer, it is permanently blocked from calling `claim_fee`, even though it holds a valid proof demonstrating it is the rightful fee recipient.

The `#[trusted_relayer]` macro is configured with bypass roles `Role::DAO` and `Role::UnrestrictedRelayer`: [4](#0-3) 

A regular fee-recipient account holds neither role, so no bypass path exists.

### Impact Explanation

Fees owed to any non-relayer fee recipient are permanently frozen inside the pending transfer storage. The `claim_fee` path is the only mechanism to release these funds. This constitutes permanent freezing of bridged fee funds, matching the "Critical — permanent freezing of bridged funds" and "Critical — fee mis-accounting" impact categories.

### Likelihood Explanation

Medium. The scenario requires a trusted relayer to designate a non-relayer account as `fee_recipient` in `sign_transfer`. This is a natural operational pattern (e.g., routing fees to a treasury or a fee-splitting contract), and nothing in the protocol prevents it. Once such a transfer is signed and completed on the destination chain, the fee is irrecoverable.

### Recommendation

Remove the `#[trusted_relayer]` attribute from `claim_fee`. The callback's `fee_recipient == predecessor_account_id` check, backed by an on-chain proof, is sufficient and correct authorization. Any account that can produce a valid proof showing it is the fee recipient should be allowed to call `claim_fee`.

```diff
-    #[payable]
-    #[trusted_relayer]
-    #[pause(except(roles(Role::DAO)))]
-    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
+    #[payable]
+    #[pause(except(roles(Role::DAO)))]
+    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
```

### Proof of Concept

1. Trusted relayer calls `sign_transfer(transfer_id, Some("treasury.near"), None)`, designating `treasury.near` as the fee recipient.
2. The MPC signs the payload; the `SignTransferEvent` is emitted and picked up by the destination chain.
3. The destination chain finalizes the transfer and emits a `FinTransfer` event that records `treasury.near` as `fee_recipient`.
4. `treasury.near` (not a trusted relayer) attempts to call `claim_fee` with the proof from the destination chain.
5. The `#[trusted_relayer]` guard panics before the proof is even verified, because `treasury.near` is not in the trusted-relayer set.
6. The fee remains locked in the pending transfer indefinitely; no other function can release it. [1](#0-0) [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L245-249)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```

**File:** near/omni-bridge/src/lib.rs (L447-452)
```rust
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L1054-1064)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L1079-1086)
```rust
        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```
