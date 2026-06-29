### Title
Decimal Normalization Floor Division Permanently Locks User Funds When Fee Is Zero - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `normalize_amount` function uses integer floor division to normalize token amounts across decimal differences between chains. When a user initiates an outbound transfer with `fee = 0`, the sub-unit remainder ("dust") from this floor division is permanently locked in the bridge contract with no mechanism to recover it, causing a direct loss of user funds.

### Finding Description
The `normalize_amount` helper performs floor division to reduce a token amount from its origin-chain precision to the bridge's internal precision:

```rust
/// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
/// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
/// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The remainder is at most `10^diff_decimals − 1` in the origin token's smallest unit. The code's own comment acknowledges two distinct outcomes:

- **fee > 0**: `claim_fee_callback` computes `fee = transfer_message.amount.0 − denormalized_amount`, which naturally captures the dust and sends it to the relayer.
- **fee = 0**: No relayer has any economic incentive to submit the proof required by `claim_fee` (a `#[trusted_relayer]`-gated call), so the dust is never recovered and remains locked in the bridge contract indefinitely.

The `claim_fee_callback` confirms this accounting:

```rust
let denormalized_amount = Self::denormalize_amount(
    fin_transfer.amount.0,
    self.token_decimals
        .get(&token_address)
        .near_expect(BridgeError::TokenDecimalsNotFound),
);
// Fee includes both the user-specified fee and any dust lost during decimal
// normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
// due to floor division, the difference naturally captures the normalization remainder.
let fee = transfer_message.amount.0 - denormalized_amount;
self.send_fee_internal(&transfer_message, fee_recipient, fee)
``` [2](#0-1) 

When `fee = 0` and no relayer calls `claim_fee`, the dust is never disbursed. The `SECURITY.md` referenced in the comment does not address this specific scenario. [3](#0-2) 

The `CLAUDE.md` false-positive note #2 ("Decimal Arithmetic Underflow") covers only the panic risk from `origin_decimals < decimals`, not the silent fund-lock when `fee = 0`. [4](#0-3) 

### Impact Explanation
Every outbound transfer where `fee = 0` and `origin_decimals > decimals` silently discards up to `10^diff_decimals − 1` of the user's tokens into the bridge escrow with no recovery path. For a token registered with `origin_decimals = 18` and `decimals = 0` (diff = 18), the maximum dust per transfer is `10^18 − 1` in the origin token's smallest unit — approaching one full token. Even at moderate differences (e.g., diff = 12), the dust is up to `10^12 − 1` units. The locked tokens are not burned (supply is preserved on NEAR) but are inaccessible to the user, constituting permanent freezing of bridged funds.

### Likelihood Explanation
Any unprivileged bridge user can trigger this by initiating an outbound transfer with `fee = 0`, which is a standard and expected usage pattern (zero-fee transfers are explicitly supported). The condition is met whenever the token's `origin_decimals` exceeds its NEAR-side `decimals`, which is the normal case for tokens normalized to lower precision. No special role, timing, or external condition is required.

### Recommendation
- **Return dust to sender**: After normalization, compute the dust (`amount % 10^diff_decimals`) and refund it to the sender before locking the normalized amount.
- **Alternatively, document and enforce minimum amounts**: Require that `amount % 10^diff_decimals == 0` so users cannot accidentally send non-representable amounts.
- **At minimum**: Update `SECURITY.md` and user-facing documentation to explicitly state that up to `10^diff_decimals − 1` tokens may be permanently lost per transfer when `fee = 0`.

### Proof of Concept
1. A token is registered with `origin_decimals = 18`, `decimals = 6` (`diff_decimals = 12`).
2. User calls `ft_on_transfer` (NEAR → Ethereum) with `amount = 1_999_999_999_999` (in origin smallest units) and `fee = 0`.
3. `normalize_amount` computes `1_999_999_999_999 / 10^12 = 1`; dust = `999_999_999_999` units.
4. The bridge locks `1_999_999_999_999` units from the user but only forwards `1` normalized unit to Ethereum.
5. Because `fee = 0`, no trusted relayer submits a `claim_fee` proof.
6. `999_999_999_999` origin-token units remain locked in the bridge contract with no recovery path for the user.

### Citations

**File:** near/omni-bridge/src/lib.rs (L1122-1133)
```rust
        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```

**File:** near/CLAUDE.md (L192-195)
```markdown
**2. Decimal Arithmetic Underflow (NOT a vulnerability)**
- Design expects `origin_decimals >= decimals` (normalization to lower precision)
- Workspace has `overflow-checks = true` in Cargo.toml
- Misconfiguration causes panic (correct fail-safe), not silent corruption
```
