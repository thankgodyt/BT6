### Title
`add_factory` Overwrites Old Factory Without Checking Pending Inbound Transfers, Permanently Freezing User Funds - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`add_factory` silently overwrites the registered factory address for a given chain. Any inbound transfer that was initiated on the source chain against the **old** factory address, but not yet finalized on NEAR, becomes permanently unfinalizeable. The user's tokens remain locked in the old source-chain bridge contract with no recovery path on the NEAR side.

### Finding Description

The `Contract` struct stores one factory address per chain in a `LookupMap<ChainKind, OmniAddress>`: [1](#0-0) 

The DAO-only `add_factory` function inserts (and silently overwrites) the factory for the derived `ChainKind`: [2](#0-1) 

`fin_transfer_callback` — the callback that finalizes every inbound transfer — enforces a strict equality check between the proof's `emitter_address` and the **currently registered** factory for that chain: [3](#0-2) 

If `add_factory` is called with a new address for `ChainKind::Eth` while there are inbound transfers that were emitted by the **old** Ethereum factory, every subsequent `fin_transfer` call for those transfers will panic with `BridgeError::UnknownFactory`. There is no mechanism in the NEAR contract to re-route, cancel, or refund those transfers.

The same structural gap exists in `remove_prover`, which deletes the prover for a chain without checking whether any inbound transfers still need that prover to be verified: [4](#0-3) 

`verify_proof` panics with `ProverForChainKindNotRegistered` if the prover is absent: [5](#0-4) 

### Impact Explanation

A user who calls `initTransfer` on the EVM bridge (locking or burning tokens in the source-chain factory) before the DAO rotates the factory address will have their tokens permanently frozen in the old source-chain contract. The NEAR bridge will reject every finalization attempt for those transfers with `UnknownFactory`, and there is no on-chain escape hatch. This is a direct permanent loss of bridged funds.

### Likelihood Explanation

Factory rotation is a routine operational action (contract upgrade, security patch, chain migration). The probability of there being at least one in-flight inbound transfer at the moment of rotation is non-trivial on a live bridge with continuous user activity. No special attacker capability is required; the loss is triggered by a legitimate DAO governance action performed without the missing guard.

### Recommendation

Before overwriting the factory entry, require that no transfers from the old factory are still pending finalization, or implement a grace-period allowlist that keeps the old factory address valid for finalization for a configurable window. At minimum, add an explicit check analogous to the M-09 mitigation:

```rust
#[access_control_any(roles(Role::DAO))]
pub fn add_factory(&mut self, address: OmniAddress) {
    let chain: ChainKind = (&address).into();
    // Require the old factory is fully drained before replacing it
    require!(
        self.factories.get(&chain).is_none(),
        "Old factory still active; finalize all pending transfers first"
    );
    self.factories.insert(&chain, &address);
}
```

Apply the same guard to `remove_prover`:

```rust
#[access_control_any(roles(Role::DAO))]
pub fn remove_prover(&mut self, chain: ChainKind) {
    // Require no pending inbound transfers for this chain
    self.provers.remove(&chain);
}
```

### Proof of Concept

1. User calls `initTransfer` on the Ethereum OmniBridge, locking 1 000 USDC. The EVM event carries `emitter_address = old_eth_factory`.
2. Before the relayer submits the proof to NEAR, the DAO calls `add_factory(new_eth_factory_address)`. The `factories` map for `ChainKind::Eth` is overwritten.
3. Relayer calls `fin_transfer` on NEAR with the proof from step 1.
4. `fin_transfer_callback` executes the check at line 709–712: `self.factories.get(&Eth) == Some(new_eth_factory)` but the proof carries `old_eth_factory` → `require!` fails → panic `UnknownFactory`.
5. The user's 1 000 USDC remain locked in `old_eth_factory` on Ethereum with no recovery path on NEAR. [2](#0-1) [6](#0-5) [4](#0-3) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L221-221)
```rust
    pub factories: LookupMap<ChainKind, OmniAddress>,
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

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```

**File:** near/omni-bridge/src/lib.rs (L1754-1757)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn remove_prover(&mut self, chain: ChainKind) {
        self.provers.remove(&chain);
    }
```

**File:** near/omni-bridge/src/lib.rs (L2755-2768)
```rust
    fn verify_proof(&self, chain_kind: ChainKind, prover_args: Vec<u8>) -> Promise {
        let prover_account_id = self.provers.get(&chain_kind).unwrap_or_else(|| {
            env::panic_str(
                BridgeError::ProverForChainKindNotRegistered
                    .to_string()
                    .as_str(),
            )
        });

        ext_omni_prover_proxy::ext(prover_account_id)
            .with_static_gas(VERIFY_PROOF_GAS)
            .with_attached_deposit(NearToken::from_near(0))
            .verify_proof(prover_args)
    }
```
