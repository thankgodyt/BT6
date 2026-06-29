Audit Report

## Title
Missing `emitter_chain` Validation Enables Cross-Chain Factory Impersonation via Crafted Wormhole VAA - (File: `near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs`)

## Summary

`ParsedVAA` parses the Wormhole VAA's `emitter_chain` field but never validates it in any `TryInto` conversion. The `emitter_address` `OmniAddress` is constructed using the chain kind from the payload's `token_address`, which is attacker-controlled, rather than from the cryptographically-bound `emitter_chain` header field. Because the bridge deploys its factory at the same address on multiple EVM chains via CREATE2, an attacker can deploy a malicious contract at that address on any other Wormhole-supported EVM chain, emit a crafted payload claiming a different chain's `ChainKind`, and cause the NEAR bridge to mint tokens with no actual lock on the claimed source chain.

## Finding Description

In `parsed_vaa.rs`, `emitter_chain` is parsed into the struct:

```rust
pub emitter_chain: u16,
pub emitter_address: Vec<u8>,
```

In every `TryInto` implementation, `self.emitter_chain` is never referenced. For `InitTransferMessage`:

```rust
emitter_address: OmniAddress::new_from_slice(
    transfer.token_address.get_chain(),  // chain kind from attacker-controlled payload
    &self.emitter_address,
)?,
```

The same pattern applies to `FinTransferMessage` (L199–203), `DeployTokenMessage` (L222–226), and `LogMetadataMessage` (L244–247). In `lib.rs`, `verify_vaa_callback` only checks the proof kind byte and dispatches on payload type — `emitter_chain` is never inspected.

The downstream factory check in `fin_transfer_callback` (L708–713) validates the emitter address against `self.factories`, but the chain kind used for the lookup is `init_transfer.emitter_address.get_chain()`, which was derived from the payload, not from the VAA header's `emitter_chain`.

The Wormhole guardian network signs the entire VAA body, which includes `emitter_chain`, `emitter_address`, and `payload`. After `verify_vaa()` succeeds, the code knows the VAA was genuinely emitted by `emitter_address` on `emitter_chain`. However, the payload's chain kind is set by the emitting contract — it is attacker-controlled. Only `emitter_chain` in the VAA header is set by the Wormhole protocol itself and cannot be forged. By ignoring `emitter_chain` and trusting the payload's chain kind, the bridge breaks the chain/domain separation guarantee.

The repository's `CLAUDE.md` marks this as a "Common False Positive" with the reasoning that "Chain ID is explicitly encoded in the payload by source bridge." This reasoning is correct for the legitimate bridge contract but is invalid for the attack scenario: a malicious contract at the same address on a different chain controls its own payload and can encode any `ChainKind` it chooses. The signed payload authenticates that *some* contract at `emitter_address` on `emitter_chain` emitted that chain kind — it does not authenticate that the chain kind matches `emitter_chain`.

## Impact Explanation

This is a **Critical** chain/domain separation flaw enabling unauthorized minting of bridged tokens on NEAR. An attacker can cause the bridge to finalize an `InitTransfer` and mint tokens to an arbitrary NEAR account with no corresponding lock of assets on the claimed source chain. This constitutes direct theft of funds from the bridge's liquidity pool and matches the allowed impact: "Cross-chain replay, message forgery, event/proof parsing flaw, or chain/domain separation flaw enabling invalid finalization or double-spending."

## Likelihood Explanation

The bridge already deploys its factory at `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989` on both Arbitrum and Base, confirming deterministic CREATE2 deployment with a public salt. The standard CREATE2 factory (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) is available on virtually all EVM chains. An attacker needs only to:
- Identify any Wormhole-supported EVM chain where the bridge has not yet deployed (or front-run deployment on a new chain)
- Deploy at the same address using the same CREATE2 factory and salt
- Emit a crafted Wormhole message

All steps are permissionless. No privileged access, leaked keys, or guardian compromise is required. The attack is repeatable until the vulnerability is patched.

## Recommendation

After `verify_vaa()` succeeds, validate that the VAA's `emitter_chain` (Wormhole chain ID) corresponds to the chain kind encoded in the payload. Maintain a mapping from Wormhole chain IDs to `ChainKind` in the prover proxy and assert consistency before constructing `emitter_address`:

```rust
let expected_chain = wormhole_chain_id_to_chain_kind(self.emitter_chain)
    .ok_or("Unknown emitter_chain")?;
require!(
    expected_chain == transfer.token_address.get_chain(),
    "emitter_chain mismatch with payload chain kind"
);
```

This ensures a VAA emitted from chain C cannot be accepted as originating from chain A, even if the emitter address bytes match the factory registered for chain A.

## Proof of Concept

**Precondition**: Bridge factory is `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989` on Arbitrum (Wormhole chain ID 23). The same address is reachable on any EVM chain via CREATE2 with the same salt.

1. Attacker deploys a malicious contract at `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989` on a third Wormhole-supported EVM chain (e.g., BNB Chain, Wormhole chain ID 4) using the same CREATE2 factory and salt as the bridge's deployment.

2. Malicious contract calls Wormhole's `publishMessage` with a Borsh-encoded `InitTransferWh` payload where `token_address = OmniAddress::Arb(some_registered_token)`, `sender = OmniAddress::Arb(attacker_evm_addr)`, `recipient = "attacker.near"`, `amount = 1_000_000`, `fee = 0`.

3. Wormhole guardians sign the VAA. The VAA body contains `emitter_chain = 4` (BNB), `emitter_address = 0xd025...`, and the crafted payload.

4. Attacker submits the VAA to `wormhole-omni-prover-proxy.verify_proof()` with `proof_kind = InitTransfer`.

5. `verify_vaa_callback` calls `parsed_vaa.try_into::<InitTransferMessage>()`. `self.emitter_chain` (= 4) is ignored. `emitter_address` is constructed as `OmniAddress::Arb(0xd025...)` because `transfer.token_address.get_chain() == ChainKind::Arb`.

6. `fin_transfer_callback` checks `self.factories.get(&ChainKind::Arb) == Some(OmniAddress::Arb(0xd025...))` — this passes because Arbitrum's factory is registered at that address.

7. The bridge mints `1_000_000` tokens to `attacker.near` with no corresponding lock on Arbitrum.

**Test plan**: Write a unit test in `near/omni-bridge/src/tests/lib_test.rs` that constructs a `ProverResult::InitTransfer` with `emitter_address = OmniAddress::Arb(factory_addr)` but sourced from a VAA with `emitter_chain` set to a non-Arbitrum Wormhole chain ID, then calls `fin_transfer_callback` and asserts that tokens are minted — demonstrating the missing validation.