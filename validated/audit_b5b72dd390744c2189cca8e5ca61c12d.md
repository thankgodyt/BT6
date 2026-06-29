Looking at the actual code to validate each claim in the report.

**Confirmed facts from the codebase:**

1. `initTransfer` and `initTransfer1155` have no `recipient` validation — only `fee >= amount` is checked before tokens are burned/locked. [1](#0-0) 

2. `OmniAddress::from_str` for an empty string `""`: `split_once(':')` returns `None`, falling back to `("eth", "")`, then attempts `"".parse::<H160>()` which fails with an error — causing the NEAR prover to panic on deserialization. [2](#0-1) 

3. `fin_transfer_callback` panics via `env::panic_str` on any prover decode failure, permanently blocking finalization. [3](#0-2) 

4. `evm/SECURITY.md` does **not** list missing `recipient` validation as a known issue. [4](#0-3) 

5. `solana/SECURITY.md` explicitly acknowledges the identical issue for Solana: *"An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed."* — but the EVM contract has no equivalent acknowledgment and no manual intervention path. [5](#0-4) 

6. No rescue, refund, or recovery function exists in `OmniBridge.sol` for failed NEAR-side finalizations. [6](#0-5) 

---

Audit Report

## Title
Missing `recipient` Validation in `OmniBridge.initTransfer()` Enables Permanent Freezing of Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary
`OmniBridge.initTransfer()` and `initTransfer1155()` accept a `recipient` string parameter that is never validated before tokens are irreversibly burned or locked on the EVM side. An empty or malformed `recipient` string causes every NEAR-side finalization attempt to panic during `OmniAddress` deserialization, with no on-chain recovery path, permanently freezing the bridged funds.

## Finding Description
`initTransfer` performs only one input guard — `fee >= amount` — before burning or locking tokens and emitting `InitTransfer`. The `recipient` string is passed through verbatim with no length or format check:

```solidity
function initTransfer(..., string calldata recipient, ...) external payable {
    currentOriginNonce += 1;
    if (fee >= amount) { revert InvalidFee(); }
    // tokens burned/locked here
    emit BridgeTypes.InitTransfer(..., recipient, ...);
}
```

The same omission exists in `initTransfer1155`.

On the NEAR side, `fin_transfer_callback` calls `Self::decode_prover_result(0)` which must deserialize the `recipient` field from the EVM event log into an `OmniAddress`. `OmniAddress::from_str` for an empty string `""` falls back to parsing `""` as an EVM `H160` address (via the `unwrap_or(("eth", input))` default), which fails. This causes `env::panic_str` to be called, permanently aborting finalization. There is no retry mechanism, no admin rescue function, and no refund path in the EVM contract for transfers whose NEAR-side finalization fails.

## Impact Explanation
Permanent freezing of bridged funds on the EVM side. Tokens are burned (bridge tokens) or transferred into the contract (native tokens) — both irreversible EVM-side operations — while the corresponding NEAR-side finalization is permanently blocked. This matches the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."* The Solana bridge's `SECURITY.md` explicitly acknowledges the identical issue class, confirming the protocol maintainers recognize it as a real fund-loss risk; the EVM contract carries no such acknowledgment and provides no manual-intervention path.

## Likelihood Explanation
Any unprivileged user can call `initTransfer` directly with no special access. Realistic trigger paths include a DApp or SDK bug that passes an uninitialized or empty recipient string, a user interacting directly with the contract via a block explorer who omits the recipient field, or a programmatic integration that fails to populate the recipient before submission. No admin compromise, social engineering, or privileged access is required. The trigger is a single public contract call.

## Recommendation
Add an explicit non-empty check for `recipient` in both `initTransfer` and `initTransfer1155` before any token transfer occurs:

```solidity
error InvalidRecipient();

function initTransfer(..., string calldata recipient, ...) external payable {
+   if (bytes(recipient).length == 0) revert InvalidRecipient();
    if (fee >= amount) revert InvalidFee();
    // ...
}
```

Apply the same guard to `initTransfer1155`. Optionally, validate that `recipient` contains a `:` separator and a recognized chain prefix to catch structurally malformed addresses before funds are committed.

## Proof of Concept
```solidity
// User holds bridge tokens
BridgeToken(tokenAddress).approve(address(omniBridge), 1000);

// Call initTransfer with empty recipient — passes all existing checks
omniBridge.initTransfer(
    tokenAddress,
    1000,   // amount
    0,      // fee (0 < 1000, passes fee check)
    0,      // nativeFee
    "",     // recipient — empty, not validated
    ""      // message
);
// Result:
// 1. Tokens are burned on EVM — irreversible.
// 2. InitTransfer event emitted with recipient="".
// 3. NEAR prover attempts OmniAddress::from_str("") → parses as ("eth","") → H160::from_str("") → Err → env::panic_str.
// 4. fin_transfer_callback panics on every relay attempt.
// 5. No rescue/refund function exists in OmniBridge.sol.
// 6. Funds are permanently frozen.
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** near/omni-types/src/lib.rs (L392-396)
```rust
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
```

**File:** near/omni-bridge/src/lib.rs (L705-707)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
```

**File:** evm/SECURITY.md (L13-21)
```markdown

Low-severity items acknowledged but not yet addressed:

- **`addCustomToken` can overwrite existing mappings** (H-01): Admin-only function. No existence check — calling with an already-mapped `nearTokenId` silently overwrites `nearToEthToken`. Accepted as operational risk
- **`pause(flags)` replaces all flags** (H-02): `_pause(flags)` does full replacement, not bitwise OR. Calling `pause(PAUSED_INIT_TRANSFER)` when `PAUSED_FIN_TRANSFER` is set will unpause finTransfer. Use `pauseAll()` for emergencies
- **`BridgeToken.initialize` stores metadata redundantly** (L-01): `__ERC20_init(name_, symbol_)` writes to parent storage that is never read (getters are overridden). Minor gas waste on init
- **`require` strings instead of custom errors** (L-02): Several locations use `require` with string messages instead of custom errors (`OmniBridge.sol:150,204,556`, `SelectivePausableUpgradable.sol:100,107`, `ENearProxy.sol:56,76,86`)
- **`OmniBridgeWormhole` has no `__gap`** (L-04): Three storage variables with no gap array. Safe as a leaf contract but would need a gap if inherited from
- **`PayloadType.ClaimNativeFee` defined but unused** (L-05): Enum value 2 is never referenced. Native fees are recovered via `finTransfer` with `tokenAddress=address(0)`
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
