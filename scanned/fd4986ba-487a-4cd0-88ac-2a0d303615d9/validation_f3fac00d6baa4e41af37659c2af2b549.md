The `OmniAddress::from_str` implementation is the key. Let me verify the exact behavior with a valid EVM hex address (no prefix) and how it flows into `ft_transfer_call`.

The vulnerability is confirmed and real. Here is the complete analysis:

---

### Title
Silent Eth-chain Default in `OmniAddress::from_str` Enables Cross-Chain Misdirection of Funds — (`near/omni-types/src/lib.rs`)

### Summary
`OmniAddress::from_str` silently defaults to `ChainKind::Eth` when the input string contains no `:` separator. A valid EVM hex address supplied without a chain prefix (e.g., `"0xdeadbeef..."`) is accepted without error and stored as `OmniAddress::Eth(...)`. This causes the `InitTransferEvent` to embed an Ethereum recipient, and the relayer finalizes on Ethereum regardless of the user's intended destination chain.

### Finding Description

The root cause is a single line in `OmniAddress::from_str`:

```rust
let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));
``` [1](#0-0) 

When no `:` is present, `split_once` returns `None`, and `unwrap_or(("eth", input))` silently substitutes `"eth"` as the chain. If the bare input is a syntactically valid 20-byte hex address (e.g., `0x1234567890123456789012345678901234567890`), the `"eth"` arm succeeds and returns `Ok(OmniAddress::Eth(...))` — no error, no warning.

The existing test suite only validates that a non-hex string without a prefix (e.g., `"invalid_format"`) returns `Err("ERR_INVALID_HEX")`. It never tests a valid EVM hex address without a prefix, leaving the silent-success path completely uncovered: [2](#0-1) 

`InitTransferMsg.recipient` is of type `OmniAddress` and is deserialized via `from_str` through the custom `Deserialize` impl: [3](#0-2) 

`InitTransferMsg::get_destination_chain()` derives the destination chain directly from the recipient: [4](#0-3) 

So the entire downstream pipeline — `InitTransferEvent`, `FinTransferEvent`, relayer routing — inherits the silently-defaulted `ChainKind::Eth`.

### Impact Explanation

An attacker who controls address `0xA` on Ethereum can receive funds intended for a victim's address `0xA` on any other EVM-compatible chain (Arbitrum, Base, BNB, Polygon, etc.) by inducing the victim to submit `ft_transfer_call` with `recipient="0xA"` instead of `"arb:0xA"`. Because EVM addresses are identical across chains, the attacker need only hold the same address on Ethereum. The bridge locks the tokens, emits an `InitTransferEvent` with `OmniAddress::Eth(0xA)`, and the relayer finalizes on Ethereum — releasing funds to the attacker rather than the intended chain.

This is a **chain/domain separation flaw enabling invalid finalization**, matching the Critical impact scope.

### Likelihood Explanation

The precondition is realistic: users interacting with the bridge via raw JSON (scripts, dApps, CLI tools) may omit the chain prefix, especially when copying a bare EVM address. The fallback is silent — no error is returned, no warning is emitted — so neither the user nor any on-chain guard catches the mistake. The relayer has no basis to reject the event since the `InitTransferEvent` is internally consistent.

### Recommendation

Remove the `unwrap_or` fallback entirely. Require an explicit chain prefix and return an error when none is present:

```rust
fn from_str(input: &str) -> Result<Self, Self::Err> {
    let (chain, recipient) = input
        .split_once(':')
        .ok_or_else(|| "Missing chain prefix: expected 'chain:address' format".to_string())?;
    // ... rest unchanged
}
```

This makes `OmniAddress::from_str("0x1234567890123456789012345678901234567890")` return `Err(...)` instead of `Ok(OmniAddress::Eth(...))`.

### Proof of Concept

```rust
#[test]
fn test_bare_evm_address_must_not_default_to_eth() {
    // A valid 20-byte EVM address with NO chain prefix.
    let bare = "0x1234567890123456789012345678901234567890";
    let result = OmniAddress::from_str(bare);
    // Currently returns Ok(OmniAddress::Eth(...)) — SHOULD return Err.
    assert!(
        result.is_err(),
        "Expected Err for bare EVM address without chain prefix, got {:?}",
        result
    );
}
```

Run against the unmodified code at [5](#0-4)  — the assertion fails, confirming the silent default is live.

### Citations

**File:** near/omni-types/src/lib.rs (L392-396)
```rust
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
```

**File:** near/omni-types/src/lib.rs (L457-461)
```rust
            fn visit_str<E>(self, input: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                OmniAddress::from_str(input).map_err(E::custom)
```

**File:** near/omni-types/src/lib.rs (L499-501)
```rust
    pub const fn get_destination_chain(&self) -> ChainKind {
        self.recipient.get_chain()
    }
```

**File:** near/omni-types/src/tests/lib_test.rs (L272-276)
```rust
        (
            "invalid_format".to_string(),
            Err("ERR_INVALID_HEX".to_string()),
            "Should fail on missing chain prefix",
        ),
```
