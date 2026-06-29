Audit Report

## Title
`MpcOmniProver` Hardcodes `EvmFinality::Latest` for Abstract Chain, Enabling Double-Spend via Block Reorg — (File: `near/omni-prover/mpc-omni-prover/src/lib.rs`)

## Summary
`MpcOmniProver::init()` configures `ChainKind::Abs` with `MpcFinality::Evm(EvmFinality::Latest)`, meaning the MPC network will fetch and sign logs from non-finalized Abstract chain blocks. Because Abstract is a ZK Stack rollup with a centralized sequencer, L2 blocks are reorganizable until a ZK proof is submitted and verified on Ethereum L1. An attacker who submits a bridge proof before that L1 finalization and then benefits from a sequencer reorg retains minted NEAR tokens while recovering their Abstract-chain tokens — a direct double-spend. A secondary defect is that `evm_log_to_rlp` silently ignores the `EvmLog.removed` field, so a log explicitly flagged as reorganized-away would still be accepted.

## Finding Description
In `MpcOmniProver::init()` (line 57), the finality map is populated with:

```rust
finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Latest));
```

`request_matches_finality` (lines 163–168) enforces an exact equality check between the submitted proof's finality and the configured value. Because the configured value is `EvmFinality::Latest`, only proofs carrying `Latest` pass — and those are the only proofs that will ever pass for Abstract. Ethereum, by contrast, is configured with `EvmFinality::Finalized` (confirmed by the test fixture at `tests.rs` line 91).

The MPC network's `verify_foreign_transaction` fetches the transaction log from the Abstract chain RPC at the `Latest` block tag. If the block containing the `initTransfer` is later reorganized away by the Abstract sequencer, the log no longer exists on-chain, but NEAR has already finalized the transfer via `add_fin_transfer` and minted tokens.

The secondary defect: `extract_evm_log` (lines 176–187) pattern-matches the `EvmLog` and passes it directly to `evm_log_to_rlp` (lines 212–231). `evm_log_to_rlp` uses only `address`, `topics`, and `data` — the `removed: bool` field (present in the struct, as seen in `tests.rs` line 30) is never read. A log with `removed: true` (set by Ethereum-compatible nodes when a log belongs to a reorganized-away block) would be accepted as a valid proof.

The replay guard in `add_fin_transfer` (`near/omni-bridge/src/lib.rs` lines 2226–2234) prevents re-submission of the same `TransferId`, but is irrelevant here: the attacker does not replay the proof; they simply benefit from the source-chain state reverting after NEAR has already minted.

## Impact Explanation
This is a Critical impact: double-spending of bridged funds. An attacker can hold the full token amount simultaneously on both Abstract chain and NEAR. This matches the allowed impact class: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."

## Likelihood Explanation
Abstract is a ZK Stack rollup with a centralized sequencer. L2 blocks are not proven on Ethereum L1 until a ZK proof is submitted and verified; until that point, the sequencer can reorganize L2 state. `EvmFinality::Latest` corresponds to the sequencer's most recent block — the state furthest from L1 finality. The attack window is the interval between the MPC network signing the payload (based on a `Latest` block) and the block being proven on L1. This window is non-zero and can span minutes to hours. An attacker who controls or colluces with the Abstract sequencer (not excluded by the rules, which only exclude NEAR validator collusion) can deliberately trigger a reorg. Even without deliberate collusion, sequencer restarts or bugs causing L2 reorgs have occurred on other ZK Stack rollups in production. The exploit is triggerable by an unprivileged external user acting as their own relayer, requiring only that a reorg occurs in the window after NEAR mints.

## Recommendation
1. Change the configured finality for `ChainKind::Abs` from `EvmFinality::Latest` to `EvmFinality::Finalized` (or at minimum `EvmFinality::Safe`) in `MpcOmniProver::init()`:
   ```rust
   finalities.insert(ChainKind::Abs, MpcFinality::Evm(EvmFinality::Finalized));
   ```
   If Abstract chain's RPC does not yet expose the `finalized` block tag, the bridge should not accept Abstract chain proofs until it does, or should use an alternative finality mechanism (e.g., waiting for L1 proof submission confirmation).

2. Add an explicit check for `evm_log.removed` in `extract_evm_log` before calling `evm_log_to_rlp`:
   ```rust
   if evm_log.removed {
       return Err(ProverError::InvalidProof.to_string());
   }
   ```

## Proof of Concept
1. Attacker calls `initTransfer` on the Abstract chain `OmniBridge`, locking/burning tokens. The transaction lands in block `N` (the current `Latest` block).
2. Attacker (acting as their own relayer) immediately calls `mpc-omni-prover.verify_proof()` on NEAR with a `MpcVerifyProofArgs` whose embedded `ForeignChainRpcRequest::Abstract` carries `finality: EvmFinality::Latest`.
3. `request_matches_finality` passes because the configured finality for `ChainKind::Abs` is `EvmFinality::Latest` (line 57 of `lib.rs`).
4. The MPC network's `verify_foreign_transaction` fetches the log from block `N` (currently canonical) and returns a signed `VerifyForeignTransactionResponse`.
5. `verify_callback` validates the payload hash and calls `extract_evm_log` → `evm_log_to_rlp`, returning a valid `ProverResult`.
6. NEAR's `omni-bridge.fin_transfer()` calls `add_fin_transfer` (marks the `TransferId` as finalised) and mints tokens to the attacker on NEAR.
7. The Abstract chain sequencer reorganizes block `N` away. The `initTransfer` transaction no longer exists on Abstract chain; the attacker's tokens are returned.
8. The attacker now holds the full token amount on both Abstract chain and NEAR — a complete double-spend.

**Minimal unit test to demonstrate the missing `removed` check:**
```rust
#[test]
fn test_removed_log_accepted() {
    let mut log = test_evm_log();
    log.removed = true; // simulate a reorganized-away log
    // evm_log_to_rlp should reject this, but it does not
    let result = evm_log_to_rlp(&log);
    assert!(result.is_ok()); // passes — demonstrates the defect
}
```