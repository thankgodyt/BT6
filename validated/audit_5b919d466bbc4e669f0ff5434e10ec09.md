### Title
Replacing the registered factory address via `add_factory` permanently freezes in-flight outbound transfers and their locked tokens - (File: `near/omni-bridge/src/lib.rs`)

### Summary
`add_factory` silently overwrites the factory address for a chain with no guard against in-flight outbound transfers. After the update, any pending transfer whose proof carries the old factory's `emitter_address` is permanently rejected by `claim_fee_callback`, leaving the transfer stuck in `pending_transfers` and the corresponding locked tokens frozen forever with no recovery path.

### Finding Description
`add_factory` performs a plain map insert keyed by `ChainKind`, unconditionally replacing the existing entry: [1](#0-0) 

`claim_fee_callback` enforces that the `emitter_address` embedded in the submitted proof exactly matches the *currently* registered factory for that chain: [2](#0-1) 

For an outbound transfer (NEAR → Foreign) the lifecycle is:
1. User calls `ft_on_transfer` → tokens are locked in `locked_tokens` and the transfer is stored in `pending_transfers`.
2. Relayer calls `sign_transfer` → MPC signs the payload.
3. Relayer submits the signed transaction to the foreign bridge contract (old factory address).
4. Foreign chain emits a `FinTransfer` event.
5. Relayer calls `claim_fee` with a proof whose `emitter_address` is the old factory.

If the DAO calls `add_factory` with a new address between steps 3 and 5, step 5 always panics at the factory check. `remove_transfer_message` at line 1094 is never reached, so the entry stays in `pending_transfers` indefinitely. [3](#0-2) 

`send_fee_internal` is never called, so `unlock_tokens_if_needed` is never invoked: [4](#0-3) 

For non-deployed (native) tokens the `locked_tokens` entry is never decremented, permanently freezing those funds. There is no cancel or admin-rescue path for stuck `pending_transfers` entries. [5](#0-4) 

### Impact Explanation
Permanent freezing of bridged funds. For non-deployed tokens, the locked balance in `locked_tokens` is never released. For deployed tokens, the tokens were already burned on initiation; the relayer can never claim the fee and the transfer record is irrecoverable. The `transfer_token_as_dao` escape hatch operates on fungible-token balances held by the bridge contract, not on the accounting in `locked_tokens` or `pending_transfers`, so it does not remediate the freeze. [6](#0-5) 

### Likelihood Explanation
`add_factory` is the standard operational call used every time a new EVM or Solana bridge deployment is registered or an existing deployment is upgraded to a new contract address. E2E pipeline scripts show it is called as a routine step during bridge setup and upgrades. [1](#0-0) 

Because outbound transfers can remain in `pending_transfers` for minutes to hours (MPC signing latency, foreign-chain congestion, relayer delays), the window during which a factory rotation collides with in-flight transfers is realistic, not theoretical.

### Recommendation
Before calling `add_factory` with a replacement address for an existing chain, the DAO should drain all pending transfers for that chain (verify `pending_transfers` is empty for the affected `ChainKind`). Two additional mitigations mirror the options from the referenced report:

1. **Retain old factory addresses**: Keep a set of historically valid factory addresses per chain and accept proofs from any of them in `claim_fee_callback`, removing an address only after all associated transfers are settled.
2. **Atomic drain-and-replace**: Add a DAO-only function that atomically claims all pending fees for the old factory (or marks them claimable against either address) before swapping the factory entry.

### Proof of Concept
```
1. User calls ft_on_transfer → init_transfer for token T to Ethereum.
   locked_tokens[(Eth, T)] += amount
   pending_transfers[transfer_id] = TransferMessage { ... }

2. Relayer calls sign_transfer → MPC signs with old factory 0xOLD.

3. Relayer submits signed tx to Ethereum bridge at 0xOLD.
   Ethereum emits FinTransfer(origin_nonce=N, emitter=0xOLD, ...).

4. DAO calls add_factory(Eth:0xNEW).
   factories[Eth] = 0xNEW   // 0xOLD is gone

5. Relayer calls claim_fee with proof { emitter_address: 0xOLD, transfer_id: N, ... }.
   claim_fee_callback:
     factories.get(Eth) == Some(0xNEW) != Some(0xOLD)  → ERR_UNKNOWN_FACTORY (panic)

6. pending_transfers[N] is never removed.
   locked_tokens[(Eth, T)] is never decremented.
   Funds are permanently frozen.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L220-242)
```rust
pub struct Contract {
    pub factories: LookupMap<ChainKind, OmniAddress>,
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
    pub finalised_utxo_transfers: LookupSet<UnifiedTransferId>,
    pub fast_transfers: LookupMap<FastTransferId, FastTransferStatusStorage>,
    pub token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>,
    pub token_address_to_id: LookupMap<OmniAddress, AccountId>,
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
    pub deployed_tokens: LookupSet<AccountId>,
    pub deployed_tokens_v2: LookupMap<AccountId, ChainKind>,
    pub token_deployer_accounts: LookupMap<ChainKind, AccountId>,
    pub mpc_signer: AccountId,
    pub current_origin_nonce: Nonce,
    // We maintain a separate nonce for each chain to optimize the storage usage on Solana by reducing the gaps.
    pub destination_nonces: LookupMap<ChainKind, Nonce>,
    pub accounts_balances: LookupMap<AccountId, StorageBalance>,
    pub wnear_account_id: AccountId,
    pub provers: UnorderedMap<ChainKind, AccountId>,
    pub init_transfer_promises: LookupMap<AccountId, CryptoHash>,
    pub utxo_chain_connectors: HashMap<ChainKind, UTXOChainConfig>,
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
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

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```

**File:** near/omni-bridge/src/lib.rs (L1511-1530)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn transfer_token_as_dao(
        &mut self,
        token: AccountId,
        amount: U128,
        recipient: AccountId,
        msg: Option<String>,
    ) -> Promise {
        if let Some(msg) = msg {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_CALL_GAS)
                .ft_transfer_call(recipient, amount, None, msg)
        } else {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2684-2684)
```rust
        self.unlock_tokens_if_needed(transfer_message.get_destination_chain(), &token, token_fee);
```
