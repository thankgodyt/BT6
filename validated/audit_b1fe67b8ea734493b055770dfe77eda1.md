### Title
`fast_fin_transfer` Bypasses `fin_transfer` Pause via `ft_on_transfer` — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The NEAR bridge exposes two separate public entry points for inbound token finalization: `fin_transfer` (proof-based) and `fast_fin_transfer` (relayer-fronted, called through `ft_on_transfer`). Because the `near-plugins` `#[pause]` macro keys each guard to its own function name, pausing `fin_transfer` does **not** pause `fast_fin_transfer`. A trusted relayer can continue to finalize inbound transfers and mint tokens to recipients even while `fin_transfer` is paused.

### Finding Description

The NEAR bridge uses `near-plugins` `#[pause]` macros. Each decorated function gets its own independent pause key derived from the function name.

`fin_transfer` is guarded by the `"fin_transfer"` pause key: [1](#0-0) 

`ft_on_transfer` is guarded by the separate `"ft_on_transfer"` pause key: [2](#0-1) 

Inside `ft_on_transfer`, when the decoded message is `FastFinTransfer`, the private `fast_fin_transfer` function is called directly — with no additional pause check: [3](#0-2) 

`fast_fin_transfer` mints or transfers tokens to the recipient, which is the same sensitive inbound-finalization action performed by `fin_transfer`: [4](#0-3) 

Similarly, `utxo_fin_transfer` (another inbound finalization path for Bitcoin/Zcash) is also dispatched through `ft_on_transfer` without checking the `fin_transfer` pause bit: [5](#0-4) 

The result: an admin who pauses `fin_transfer` to halt inbound transfers during a security incident leaves the `fast_fin_transfer` path fully open. To close it, the admin would have to pause `ft_on_transfer` instead — but that also blocks all outbound transfers (`init_transfer`), making selective pausing of inbound-only flows impossible.

### Impact Explanation
When `fin_transfer` is paused (e.g., in response to a compromised prover, suspicious minting activity, or an ongoing exploit), trusted relayers can still call `ft_on_transfer` with a `FastFinTransfer` payload to mint bridge tokens to arbitrary recipients on NEAR. This directly undermines the pause mechanism's ability to halt inbound token flows, potentially allowing continued unauthorized minting during an active incident.

### Likelihood Explanation
Exploitation requires the attacker to hold trusted-relayer status, which is an externally reachable role (not an admin). A malicious or compromised trusted relayer can exploit this at any time `fin_transfer` is paused but `ft_on_transfer` is not. The conditions are realistic: the two pause states are independently managed, and an operator responding to an incident is likely to pause only `fin_transfer`.

### Recommendation
Add an explicit check for the `fin_transfer` pause bit inside `fast_fin_transfer` (and `utxo_fin_transfer`), mirroring the pattern used in `fin_transfer` itself. Alternatively, introduce a dedicated `PAUSED_FIN_TRANSFER` flag that is checked by all inbound-finalization code paths regardless of which public entry point is used.

### Proof of Concept

1. Admin detects suspicious activity and calls `pause("fin_transfer")` to halt proof-based inbound transfers.
2. `fin_transfer` is now blocked for all non-DAO callers.
3. A trusted relayer constructs a `FastFinTransferMsg` for a transfer ID that has not yet been finalized.
4. The relayer calls `ft_transfer_call` on a NEAR token contract, sending tokens to the bridge with `msg = {"FastFinTransfer": {...}}`.
5. The token contract invokes `ft_on_transfer` on the bridge. The `"ft_on_transfer"` pause key is **not** set, so execution proceeds.
6. `fast_fin_transfer` runs, mints tokens to the recipient, and records the fast transfer — all while `fin_transfer` is paused.
7. The pause intended to stop inbound minting has no effect on this path.

### Citations

**File:** near/omni-bridge/src/lib.rs (L252-253)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
```

**File:** near/omni-bridge/src/lib.rs (L265-267)
```rust
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
```

**File:** near/omni-bridge/src/lib.rs (L268-274)
```rust
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
```

**File:** near/omni-bridge/src/lib.rs (L672-673)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** near/omni-bridge/src/lib.rs (L877-882)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            recipient,
            amount_without_fee,
            &fast_transfer.msg,
        )
```
