### Title
Missing `emitter_chain` Validation in Wormhole VAA Processing Enables Cross-Chain Factory Impersonation - (File: `near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs`)

---

### Summary

The `wormhole-omni-prover-proxy` parses the Wormhole VAA's `emitter_chain` field but **never validates it** against any expected chain. Chain identity is derived entirely from the payload's `token_address` chain kind. Because the bridge deploys factories at identical addresses on multiple EVM chains, an attacker can deploy a malicious contract at a known factory address on a different chain, emit forged Wormhole messages claiming to originate from a legitimate chain, and cause the NEAR bridge to mint tokens without any actual lock on the source chain.

---

### Finding Description

In `parsed_vaa.rs`, the `ParsedVAA` struct parses `emitter_chain` from the VAA body: [1](#0-0) 

However, in every `TryInto` conversion, `self.emitter_chain` is **never referenced**. The chain kind used to construct the `emitter_address` `OmniAddress` is taken from the payload's `token_address`, not from the VAA header: [2](#0-1) 

The same pattern applies to `FinTransferMessage`, `DeployTokenMessage`, and `LogMetadataMessage`: [3](#0-2) [4](#0-3) [5](#0-4) 

The `verify_vaa_callback` in `lib.rs` never checks `emitter_chain` either — it only validates the proof kind byte and dispatches on payload type: [6](#0-5) 

The downstream factory check in the NEAR bridge's `fin_transfer_callback` validates the emitter address against the `factories` map, but the chain kind used for the lookup comes from the payload-derived `emitter_address.get_chain()`, not from the VAA's `emitter_chain`: [7](#0-6) 

---

### Impact Explanation

The Wormhole guardian network signs the VAA body, which includes `emitter_chain`, `emitter_address`, and `payload`. After `verify_vaa()` succeeds, the code knows the VAA was genuinely emitted by `emitter_address` on `emitter_chain`. However, because `emitter_chain` is never cross-validated against the chain kind encoded in the payload, the following attack is possible:

1. An attacker deploys a malicious contract on chain A at address `X`.
2. `X` is identical to the bridge factory address on chain B (realistic — Arbitrum and Base both use `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`).
3. The malicious contract emits a Wormhole message with a payload that encodes chain B's `ChainKind` in `token_address` and `sender`.
4. Wormhole guardians sign the VAA (`emitter_chain` = chain A's Wormhole ID, `emitter_address` = `X`).
5. The NEAR prover: `emitter_chain` is ignored; `emitter_address` is constructed as `OmniAddress::ChainB(X)` because the payload says chain B; the factories check passes because `factories[ChainKind::B] == OmniAddress::ChainB(X)`.
6. The NEAR bridge processes the forged `InitTransfer` and mints tokens on NEAR with no actual lock on chain B.

This enables **unauthorized minting of bridged tokens on NEAR**, constituting theft of funds from the bridge's liquidity.

---

### Likelihood Explanation

The bridge already deploys factories at the same address on multiple EVM chains (Arbitrum and Base share `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`). Any EVM chain supported by Wormhole where the bridge has not yet deployed — or where an attacker can front-run deployment using a public CREATE2 factory — provides the necessary foothold. The attacker needs no privileged access: deploying a contract and submitting a VAA are both permissionless operations.

---

### Recommendation

After `verify_vaa()` succeeds, validate that the VAA's `emitter_chain` (Wormhole chain ID) corresponds to the expected chain kind encoded in the payload. Maintain a mapping from Wormhole chain IDs to `ChainKind` and assert consistency:

```rust
// After parsing:
let expected_chain = wormhole_chain_id_to_chain_kind(parsed_vaa.emitter_chain)?;
require!(
    expected_chain == transfer.token_address.get_chain(),
    "emitter_chain mismatch"
);
```

This ensures a VAA emitted from chain A cannot be accepted as originating from chain B, even if the emitter address bytes match a factory on chain B.

---

### Proof of Concept

**Setup**: Bridge factory on Arbitrum and Base is `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989`. Wormhole supports both chains (chain IDs 23 and 30 respectively).

**Step 1**: Attacker deploys a malicious contract at `0xd025b38762B4A4E36F0Cde483b86CB13ea00D989` on a third Wormhole-supported EVM chain (e.g., using the deterministic CREATE2 proxy with the same salt as the bridge's deployment).

**Step 2**: Malicious contract calls Wormhole's `publishMessage` with a Borsh-encoded `InitTransferWh` payload where `token_address = OmniAddress::Arb(some_token)`, `sender = OmniAddress::Arb(attacker)`, `recipient = "attacker.near"`, `amount = 1_000_000`.

**Step 3**: Wormhole guardians sign the VAA. The VAA body contains `emitter_chain = <third chain's Wormhole ID>`, `emitter_address = 0xd025...`.

**Step 4**: Attacker submits the VAA to `wormhole-omni-prover-proxy.verify_proof()`.

**Step 5**: `verify_vaa_callback` calls `parsed_vaa.try_into()` for `InitTransfer`. `emitter_chain` is ignored. `emitter_address` is constructed as `OmniAddress::Arb(0xd025...)` because `token_address.get_chain() == ChainKind::Arb`.

**Step 6**: `fin_transfer_callback` checks `factories[ChainKind::Arb] == OmniAddress::Arb(0xd025...)` — this passes because Arbitrum's factory is indeed at that address.

**Step 7**: NEAR bridge mints tokens to `attacker.near` with no corresponding lock on Arbitrum. [8](#0-7) [9](#0-8)

### Citations

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L25-26)
```rust
    pub emitter_chain: u16,
    pub emitter_address: Vec<u8>,
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L156-182)
```rust
impl TryInto<InitTransferMessage> for ParsedVAA {
    type Error = String;

    fn try_into(self) -> Result<InitTransferMessage, String> {
        let transfer: InitTransferWh = borsh::from_slice(&self.payload).map_err(stringify)?;

        if transfer.payload_type != ProofKind::InitTransfer {
            return Err("Invalid proof kind".to_owned());
        }

        Ok(InitTransferMessage {
            token: transfer.token_address.clone(),
            amount: transfer.amount.into(),
            fee: Fee {
                fee: transfer.fee.into(),
                native_fee: transfer.native_fee.into(),
            },
            recipient: transfer.recipient.parse().map_err(stringify)?,
            origin_nonce: transfer.origin_nonce,
            sender: transfer.sender,
            msg: transfer.message,
            emitter_address: OmniAddress::new_from_slice(
                transfer.token_address.get_chain(),
                &self.emitter_address,
            )?,
        })
    }
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L199-203)
```rust
            emitter_address: OmniAddress::new_from_slice(
                transfer.token_address.get_chain(),
                &self.emitter_address,
            )?,
        })
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L222-226)
```rust
            emitter_address: OmniAddress::new_from_slice(
                parsed_payload.token_address.get_chain(),
                &self.emitter_address,
            )?,
        })
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L244-247)
```rust
            symbol: parsed_payload.symbol,
            decimals: parsed_payload.decimals,
            emitter_address: OmniAddress::new_from_slice(chain_kind, &self.emitter_address)?,
        })
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/lib.rs (L61-85)
```rust
    pub fn verify_vaa_callback(
        &mut self,
        proof_kind: ProofKind,
        vaa: String,
        #[callback_result] gov_idx: &Result<u32, PromiseError>,
    ) -> Result<ProverResult, String> {
        if gov_idx.is_err() {
            return Err("Proof is not valid!".to_owned());
        }

        let h = hex::decode(vaa).expect("invalidVaa");
        let parsed_vaa = parsed_vaa::ParsedVAA::parse(&h);

        require!(
            u8::from(proof_kind) == parsed_vaa.payload[0],
            "Invalid proof kind"
        );

        match proof_kind {
            ProofKind::InitTransfer => Ok(ProverResult::InitTransfer(parsed_vaa.try_into()?)),
            ProofKind::FinTransfer => Ok(ProverResult::FinTransfer(parsed_vaa.try_into()?)),
            ProofKind::DeployToken => Ok(ProverResult::DeployToken(parsed_vaa.try_into()?)),
            ProofKind::LogMetadata => Ok(ProverResult::LogMetadata(parsed_vaa.try_into()?)),
        }
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
