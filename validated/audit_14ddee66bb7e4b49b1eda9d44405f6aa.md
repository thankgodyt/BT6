The exploit path is real and concrete. Let me trace it fully.

**Full chain:**

1. **EVM `initTransfer`** — no recipient format validation; accepts any `string calldata recipient` [1](#0-0) 

2. **EVM prover `TryFromLog` for `InitTransferMessage`** — calls `.parse()` on the raw recipient string to produce an `OmniAddress`, propagating any parse error as `Err` [2](#0-1) 

3. **`OmniAddress::from_str`** — returns `Err("Chain X is not supported")` for any unknown chain prefix, and `Err(...)` for invalid address bytes on known chains [3](#0-2) 

4. **`evm-prover::verify_proof_callback`** — `parse_evm_proof` returns `Err`, and with `#[handle_result]` the prover promise result is a **failed promise** [4](#0-3) 

5. **`fin_transfer_callback`** — `decode_prover_result(0)` returns `Err(PromiseError::Failed)` for a failed promise; the `let Ok(...)` pattern fails and `env::panic_str(BridgeError::InvalidProofMessage)` is called — the callback panics, no transfer record is ever written, and the EVM-locked tokens are permanently frozen [5](#0-4) 

The same parse-and-propagate pattern exists in the Wormhole prover path and the Starknet prover path: [6](#0-5) [7](#0-6) 

---

### Title
Malformed `recipient` string in EVM `initTransfer` permanently freezes bridged tokens — (`evm/src/omni-bridge/contracts/BridgeTypes.sol`, `near/omni-types/src/evm/events.rs`)

### Summary
`OmniBridge.initTransfer` accepts an arbitrary `string calldata recipient` with no format validation. When the EVM prover parses the resulting on-chain log, it calls `OmniAddress::from_str` on that string. Any string that fails parsing (e.g., unknown chain prefix, invalid address bytes) causes the prover promise to fail, which causes `fin_transfer_callback` to panic with `InvalidProofMessage` before recording any transfer. The tokens burned/locked on EVM can never be recovered.

### Finding Description
`OmniBridge.initTransfer` burns or locks the caller's tokens and emits `BridgeTypes.InitTransfer` with the raw `recipient` string: [8](#0-7) 

The EVM prover's `TryFromLog` implementation for `InitTransferMessage` calls:
```rust
recipient: event.data.recipient.parse().map_err(stringify)?
``` [2](#0-1) 

`OmniAddress::from_str` rejects any string whose chain prefix is not one of the 13 known chains, and rejects valid-prefix strings whose address portion fails type-specific parsing (e.g., non-hex for EVM chains, invalid base58 for Solana): [3](#0-2) 

A parse failure propagates as `Err` out of `parse_evm_proof`, causing the `#[handle_result]` prover callback to return a failed promise. `fin_transfer_callback` then hits:
```rust
let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
    env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
};
``` [5](#0-4) 

The callback panics. No transfer record is written to `pending_transfers`. The EVM tokens are already burned/locked and there is no on-chain cancellation or refund path.

### Impact Explanation
Permanent freezing of bridged funds. Any user who calls `initTransfer` with a recipient string that is syntactically valid UTF-8 but not a valid `OmniAddress` (e.g., `"!!!invalid!!!"`, `"eth:notanaddress"`, `"near:INVALID!!!"`) will have their tokens burned/locked on EVM with no possibility of finalization or recovery on NEAR.

### Likelihood Explanation
A malicious actor can deliberately trigger this to grief other users or destroy their own tokens. More critically, a user who makes a typo in the recipient address (e.g., `"eth:0xGGGG..."`) will also permanently lose funds. The EVM contract provides no guard whatsoever.

### Recommendation
Add recipient format validation in `OmniBridge.initTransfer` on the EVM side. Since Solidity cannot run `OmniAddress::from_str`, the minimal fix is to validate that the `recipient` string matches the expected `chain:address` pattern (e.g., via a regex-equivalent check or a whitelist of valid chain prefixes with length/character constraints). Alternatively, the NEAR `fin_transfer_callback` should handle a failed prover promise gracefully (e.g., by logging and returning rather than panicking), so that the transfer can be retried or administratively cancelled.

### Proof of Concept
1. Deploy the EVM bridge on a local testnet.
2. Call `initTransfer(tokenAddress, amount, fee, 0, "!!!invalid!!!", "")` — tokens are burned, `InitTransfer` event emitted with `recipient = "!!!invalid!!!"`.
3. Confirm tokens are gone from the caller's balance.
4. Submit the proof to NEAR `fin_transfer`. The EVM prover calls `parse_evm_proof` → `event.data.recipient.parse()` → `OmniAddress::from_str("!!!invalid!!!")` → `Err("Chain !!! is not supported")` → prover promise fails.
5. `fin_transfer_callback` panics with `InvalidProofMessage`. No transfer record exists. Tokens are permanently frozen.

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

**File:** near/omni-types/src/evm/events.rs (L127-127)
```rust
            recipient: event.data.recipient.parse().map_err(stringify)?,
```

**File:** near/omni-types/src/lib.rs (L392-411)
```rust
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

**File:** near/omni-prover/evm-prover/src/lib.rs (L117-123)
```rust
    ) -> Result<ProverResult, String> {
        if block_hash != Some(expected_block_hash) {
            return Err(ProverError::InvalidBlockHash.to_string());
        }

        parse_evm_proof(kind, self.chain_kind, log_entry_data)
    }
```

**File:** near/omni-bridge/src/lib.rs (L705-707)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
```

**File:** near/omni-prover/wormhole-omni-prover-proxy/src/parsed_vaa.rs (L173-173)
```rust
            recipient: transfer.recipient.parse().map_err(stringify)?,
```

**File:** near/omni-types/src/starknet/events.rs (L61-61)
```rust
    let recipient: OmniAddress = recipient_str.parse().map_err(stringify)?;
```
