### Title
Stale Factory Address Check in `claim_fee_callback` Permanently Locks Relayer Fees After Factory Update — (`File: near/omni-bridge/src/lib.rs`)

### Summary

`claim_fee_callback` validates the emitter address against the **current** factory stored in `self.factories` (a `LookupMap<ChainKind, OmniAddress>` that holds exactly one factory per chain). Because `add_factory` overwrites the existing entry for a chain, any pending fee claim whose proof references the **old** factory address will permanently fail after a factory upgrade, locking the relayer's fee and leaving the transfer message stranded in `pending_transfers`.

### Finding Description

The `factories` map stores a single factory address per `ChainKind`: [1](#0-0) 

`add_factory` unconditionally overwrites the existing entry: [2](#0-1) 

`claim_fee_callback` then validates the proof's emitter address against the **current** factory value at claim time, not at the time the transfer was originally processed: [3](#0-2) 

`remove_transfer_message` (which clears the pending entry and triggers `unlock_tokens_if_needed`) is only reached **after** this check passes: [4](#0-3) 

If the DAO calls `add_factory` with a new EVM bridge address (e.g., after a contract upgrade), any relayer holding a proof whose `emitter_address` is the old factory will hit `BridgeError::UnknownFactory` and be permanently unable to claim their fee. The transfer message remains in `pending_transfers` indefinitely, and `locked_tokens` is never decremented.

### Impact Explanation

Two concrete harms result:

1. **Permanent relayer fee loss.** The fee embedded in the transfer message (the difference between the locked amount and the amount delivered to the recipient) can never be extracted. It is frozen inside the bridge contract.

2. **Escrow mis-accounting (`locked_tokens` never decremented).** `unlock_tokens_if_needed` is called inside `send_fee_internal`, which is only reached after the factory check. With the check failing, `locked_tokens` for the affected `(ChainKind, token_id)` pair remains inflated, corrupting the bridge's internal accounting of how many tokens are held in escrow for each destination chain.

This matches the allowed impact scope: *"fee mis-accounting … that changes user or protocol balances"* and *"permanent freezing of bridged funds."* [5](#0-4) [6](#0-5) 

### Likelihood Explanation

Factory upgrades are a normal, expected operational event (the DAO calls `add_factory` to point to a redeployed or upgraded EVM bridge). The e2e scripts and integration tests show `add_factory` being called as a routine setup step. Any relayer that processed transfers in the window between the old and new factory deployment will be unable to claim fees for those transfers. No attacker action is required; the trigger is a legitimate DAO governance call. [7](#0-6) 

### Recommendation

Replace the point-in-time factory lookup with a check against the factory address **recorded at the time the transfer was accepted**. One approach: store the emitter address inside `TransferMessageStorage` when `fin_transfer_callback` creates the pending entry, and validate `claim_fee_callback`'s proof against that stored value instead of the live `self.factories` map. Alternatively, maintain a historical set of valid factory addresses per chain so that old-factory proofs remain valid after an upgrade.

### Proof of Concept

1. DAO calls `add_factory("eth:0xOLD_BRIDGE")` — factory for `ChainKind::Eth` is `0xOLD_BRIDGE`.
2. User initiates a NEAR→ETH transfer; relayer finalises it on Ethereum via `0xOLD_BRIDGE`.
3. DAO upgrades the EVM bridge and calls `add_factory("eth:0xNEW_BRIDGE")` — `self.factories[Eth]` is now `0xNEW_BRIDGE`.
4. Relayer calls `claim_fee` with a proof whose `emitter_address = eth:0xOLD_BRIDGE`.
5. Inside `claim_fee_callback`:
   ```
   self.factories.get(&ChainKind::Eth)  // returns Some(eth:0xNEW_BRIDGE)
   == Some(eth:0xOLD_BRIDGE)            // false → panic UnknownFactory
   ```
6. The call reverts. The transfer message stays in `pending_transfers`. `locked_tokens` is never decremented. The relayer's fee is permanently frozen. [3](#0-2) [2](#0-1)

### Citations

**File:** near/omni-bridge/src/lib.rs (L221-221)
```rust
    pub factories: LookupMap<ChainKind, OmniAddress>,
```

**File:** near/omni-bridge/src/lib.rs (L1054-1063)
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
```

**File:** near/omni-bridge/src/lib.rs (L1087-1092)
```rust
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1094-1094)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);
```

**File:** near/omni-bridge/src/lib.rs (L1131-1133)
```rust
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```

**File:** near/omni-bridge/src/lib.rs (L2684-2684)
```rust
        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);
```
