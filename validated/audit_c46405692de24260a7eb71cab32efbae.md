### Title
Missing Recipient Validation in Solana `init_transfer` Causes Permanent Fund Loss via Unparseable Wormhole VAA — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The Solana bridge program accepts any arbitrary string as the `recipient` field in `InitTransferPayload` without validation. Tokens are burned or locked before the Wormhole message is posted. On the NEAR side, the Wormhole prover proxy attempts to parse the raw recipient string into an `OmniAddress` via `OmniAddress::from_str()`. If the string is malformed (empty, missing chain prefix, invalid NEAR account ID characters, exceeds 64 bytes, etc.), the prover returns an error, `fin_transfer_callback` panics, and the tokens are permanently unrecoverable. There is no refund path on Solana.

---

### Finding Description

**Step 1 — Solana `init_transfer` performs zero recipient validation.**

`InitTransferPayload.recipient` is a plain `String`: [1](#0-0) 

The `process()` handler only checks `amount > fee` and handles token locking/burning. No check on `recipient`: [2](#0-1) 

`serialize_for_near` embeds the raw string directly into the Wormhole payload: [3](#0-2) 

**Step 2 — Tokens are irrevocably burned or locked before the message is posted.**

For native tokens, `transfer_checked` moves them into the vault. For bridged tokens, `burn` destroys them. Both happen before `post_message`. There is no rollback or refund instruction anywhere in the Solana program.

**Step 3 — NEAR Wormhole prover proxy parses the recipient string.**

`InitTransferWh` deserializes `recipient` as a raw `String`: [4](#0-3) 

The conversion to `InitTransferMessage` calls `.parse()` on it, which invokes `OmniAddress::from_str()`: [5](#0-4) 

`OmniAddress::from_str` enforces strict rules: requires a `chain:address` prefix, and for `near:` the account ID must be 2–64 lowercase alphanumeric characters. An empty string, a string without a `:`, a string with uppercase letters, null bytes, or a NEAR account ID exceeding 64 bytes all return `Err`: [6](#0-5) 

When `.parse()` fails, `verify_vaa_callback` returns `Err(...)`: [7](#0-6) 

**Step 4 — `fin_transfer_callback` panics; tokens are permanently lost.**

`fin_transfer_callback` requires `ProverResult::InitTransfer` from the prover. If the prover returned an error, the callback panics with `BridgeError::InvalidProofMessage`: [8](#0-7) 

The Solana vault retains the locked tokens (or the burned bridged tokens are gone) with no recovery mechanism.

---

### Impact Explanation

Any user who calls `init_transfer` or `init_transfer_sol` on Solana with a recipient string that does not parse as a valid `OmniAddress` (e.g., `""`, `"alice"`, `"near:ALICE"`, `"near:" + "a"×65`, `"near:\x00"`) will have their tokens permanently destroyed or locked. The Wormhole VAA is valid and accepted by guardians, but the NEAR prover rejects the payload at parse time. No finalization is possible, and no refund path exists on Solana. This violates the invariant that every successful `init_transfer` on Solana has a reachable finalization path on NEAR, constituting irreversible fund loss.

---

### Likelihood Explanation

The recipient string is a free-form user input with no on-chain guard. A user who mistypes the chain prefix (e.g., `"alice.near"` instead of `"near:alice.near"`), uses uppercase, or exceeds the 64-byte NEAR account ID limit will silently lose funds. The EVM bridge's `initTransferExtension` has the same pattern (raw `string calldata recipient`), confirming this is a systemic design gap, not an isolated oversight. [9](#0-8) 

---

### Recommendation

Validate `payload.recipient` in the Solana `InitTransfer::process()` and `InitTransferSol::process()` before burning or locking tokens:

1. Require the string to contain exactly one `:` separator.
2. Require the chain prefix to be one of the supported chain identifiers.
3. For `near:` recipients, enforce NEAR account ID rules: 2–64 bytes, lowercase alphanumeric plus `-`, `_`, `.`, no leading/trailing `.`.
4. Reject the instruction with `ErrorCode::InvalidArgs` if any check fails, so the transaction reverts before funds are moved.

---

### Proof of Concept

```rust
// Solana-side: call init_transfer with an invalid recipient
let payload = InitTransferPayload {
    amount: 1_000_000,
    recipient: "".to_string(),          // or "ALICE.NEAR", or "near:" + "a".repeat(65)
    fee: 0,
    native_fee: 0,
    message: String::new(),
};
// → tokens burned/locked, Wormhole VAA posted

// NEAR-side: relayer submits VAA to fin_transfer
// → verify_vaa_callback calls: "".parse::<OmniAddress>()
//   OmniAddress::from_str("") → splits on ':' → ("eth", "") → H160 parse fails → Err
// → verify_vaa_callback returns Err
// → fin_transfer_callback panics: BridgeError::InvalidProofMessage
// → tokens permanently unrecoverable
```

Fuzz targets: `recipient` values of `""`, `"alice.near"` (missing prefix), `"near:ALICE"` (uppercase), `"near:" + "a"×65` (too long), `"near:\x00"` (null byte). All fail `OmniAddress::from_str` and produce no finalization path.

### Citations

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L7-14)
```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L37-38)
```rust
        // 7. recipient
        self.recipient.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L72-130)
```rust
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.amount > payload.fee, ErrorCode::InvalidFee);

        if payload.native_fee > 0 {
            transfer(
                CpiContext::new(
                    self.common.system_program.to_account_info(),
                    Transfer {
                        from: self.user.to_account_info(),
                        to: self.sol_vault.to_account_info(),
                    },
                ),
                payload.native_fee,
            )?;
        }

        if let Some(vault) = &self.vault {
            // Native version. We have a proof of token registration by vault existence
            transfer_checked(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    TransferChecked {
                        from: self.from.to_account_info(),
                        to: vault.to_account_info(),
                        authority: self.user.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
                self.mint.decimals,
            )?;
        } else {
            // Bridged version. May be a fake token with our authority set but it will be ignored on the near side
            require!(
                self.mint.mint_authority.contains(self.authority.key),
                ErrorCode::InvalidBridgedToken
            );

            burn(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    Burn {
                        mint: self.mint.to_account_info(),
                        from: self.from.to_account_info(),
                        authority: self.user.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
            )?;
        }

        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;

        Ok(())
    }
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L143-154)
```rust
#[derive(Debug, BorshDeserialize)]
struct InitTransferWh {
    payload_type: ProofKind,
    sender: OmniAddress,
    token_address: OmniAddress,
    origin_nonce: Nonce,
    amount: u128,
    fee: u128,
    native_fee: u128,
    recipient: String,
    message: String,
}
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L173-173)
```rust
            recipient: transfer.recipient.parse().map_err(stringify)?,
```

**File:** near/omni-types/src/lib.rs (L389-411)
```rust
impl FromStr for OmniAddress {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/lib.rs (L79-84)
```rust
        match proof_kind {
            ProofKind::InitTransfer => Ok(ProverResult::InitTransfer(parsed_vaa.try_into()?)),
            ProofKind::FinTransfer => Ok(ProverResult::FinTransfer(parsed_vaa.try_into()?)),
            ProofKind::DeployToken => Ok(ProverResult::DeployToken(parsed_vaa.try_into()?)),
            ProofKind::LogMetadata => Ok(ProverResult::LogMetadata(parsed_vaa.try_into()?)),
        }
```

**File:** near/omni-bridge/src/lib.rs (L705-707)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L125-140)
```text
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
```
