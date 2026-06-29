### Title
`add_factory` Silently Overwrites Existing Factory Address, Permanently Freezing In-Flight Foreign→NEAR Transfers - (File: near/omni-bridge/src/lib.rs)

### Summary
The DAO-callable `add_factory` function in the NEAR `omni-bridge` contract unconditionally overwrites the registered factory address for a given chain. Because `fin_transfer_callback` and `claim_fee_callback` both hard-require that the proof's emitter address exactly matches the currently registered factory, any Foreign→NEAR transfer that was initiated against the old factory but not yet finalized on NEAR becomes permanently unfinalizeable after the factory address is updated.

### Finding Description

`add_factory` is the sole mechanism for registering the authoritative bridge contract address for each foreign chain: [1](#0-0) 

```rust
#[access_control_any(roles(Role::DAO))]
pub fn add_factory(&mut self, address: OmniAddress) {
    self.factories.insert(&(&address).into(), &address);
}
```

The `factories` field is a `LookupMap<ChainKind, OmniAddress>` — one slot per chain: [2](#0-1) 

`insert` on a `LookupMap` silently replaces any existing value. There is no guard (`require!`, existence check, or migration step) preventing an overwrite of a live factory address.

Both critical finalization paths perform an exact equality check against the currently registered factory:

**`fin_transfer_callback`** (Foreign→NEAR finalization): [3](#0-2) 

```rust
require!(
    self.factories
        .get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
```

**`claim_fee_callback`** (relayer fee settlement for NEAR→Foreign transfers): [4](#0-3) 

```rust
require!(
    self.factories
        .get(&fin_transfer.emitter_address.get_chain())
        == Some(fin_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
```

Once the factory address is overwritten, every proof whose `emitter_address` references the old factory contract will be rejected with `ERR_UNKNOWN_FACTORY`. There is no cancel, refund, or recovery path for Foreign→NEAR transfers: the only way to finalize them is through `fin_transfer`, which requires the factory check to pass. [5](#0-4) 

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

Consider the following scenario:

1. A user initiates a transfer on the Ethereum `OmniBridge.sol` (old factory address), locking or burning their ERC-20 tokens. The event is emitted on-chain.
2. Before the relayer submits the NEAR-side `fin_transfer` proof, the DAO calls `add_factory` with the address of a newly deployed Ethereum bridge contract (e.g., after an EVM-side upgrade).
3. The relayer submits the proof. `fin_transfer_callback` reads `self.factories.get(ChainKind::Eth)` and gets the new address. The proof's `emitter_address` is the old address → `ERR_UNKNOWN_FACTORY` → transaction reverts.
4. The user's tokens are locked in the old EVM factory with no on-chain mechanism to release them on NEAR. The transfer is permanently unfinalizeable.

The same overwrite also breaks `claim_fee` for any NEAR→Foreign pending transfers whose fee-settlement proof references the old factory, leaving those `pending_transfers` entries permanently stranded. [6](#0-5) 

### Likelihood Explanation

**Realistic.** The DAO has a legitimate operational reason to call `add_factory` when upgrading the foreign bridge contract (bug fix, feature addition, security patch). The function's name and signature give no indication that it is destructive to in-flight transfers. A DAO upgrade workflow that deploys a new EVM contract and then calls `add_factory` with the new address — without first draining all pending proofs — would silently trigger this freeze. The mainnet bridge already has active transfers at any given time, making the window of exposure non-trivial.

### Recommendation

1. **Prevent silent overwrites**: Add a guard that panics if a factory for the given chain is already registered:
   ```rust
   require!(
       self.factories.get(&chain_kind).is_none(),
       "Factory already set for this chain"
   );
   ```
2. **Or implement a two-step migration**: Introduce a `replace_factory` function that accepts both the old and new address, verifies the old address matches the current registration, and only proceeds when `pending_transfers` for that chain is empty (or provides an explicit acknowledgement of the risk).
3. **Alternatively**, remove the ability to change the factory address entirely (analogous to the M-02 recommendation), and rely on contract upgrades for factory changes.

### Proof of Concept

```
1. DAO calls add_factory(OmniAddress::Eth(old_factory_addr))
   → factories[ChainKind::Eth] = old_factory_addr

2. User calls initTransfer on old_factory_addr (Ethereum)
   → tokens locked on Ethereum, event emitted

3. DAO calls add_factory(OmniAddress::Eth(new_factory_addr))
   → factories[ChainKind::Eth] = new_factory_addr  (old entry silently overwritten)

4. Relayer calls fin_transfer(chain_kind=Eth, prover_args=<proof from old_factory_addr>)
   → fin_transfer_callback:
      self.factories.get(ChainKind::Eth) == Some(new_factory_addr)
      proof.emitter_address              == old_factory_addr
      → require! fails → ERR_UNKNOWN_FACTORY → panic

5. User's tokens remain locked on Ethereum forever.
   No recovery path exists in the NEAR contract.
``` [1](#0-0) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L221-221)
```rust
    pub factories: LookupMap<ChainKind, OmniAddress>,
```

**File:** near/omni-bridge/src/lib.rs (L670-696)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
        require!(
            args.storage_deposit_actions.len() <= 3,
            BridgeError::InvalidStorageAccountsLen.as_ref()
        );
        let mut main_promise = self.verify_proof(args.chain_kind, args.prover_args);

        let mut attached_deposit = env::attached_deposit();

        for action in &args.storage_deposit_actions {
            main_promise =
                main_promise.and(Self::check_or_pay_ft_storage(action, &mut attached_deposit));
        }

        main_promise.then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(attached_deposit)
                .with_static_gas(FIN_TRANSFER_CALLBACK_GAS)
                .fin_transfer_callback(
                    &args.storage_deposit_actions,
                    env::predecessor_account_id(),
                ),
        )
    }
```

**File:** near/omni-bridge/src/lib.rs (L705-713)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1057-1063)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```
