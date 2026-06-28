### Title
No Recipient Validation Before Token Burn/Lock in `initTransfer` Allows Permanent Loss of Bridged Funds — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

The `initTransfer` and `initTransfer1155` functions in `OmniBridge.sol` burn or lock user tokens before any validation of the `recipient` string. An unprivileged user who supplies an invalid or unresolvable NEAR address causes their tokens to be permanently burned/locked on EVM with no on-chain recovery path, because the NEAR side will fail to finalize the transfer. The identical root cause exists in the Starknet `init_transfer`.

---

### Finding Description

In `OmniBridge.sol`, `initTransfer` performs the token burn/lock before the `InitTransfer` event is emitted, and the `recipient` parameter is a free-form `string calldata` with no format validation at any point in the function.

The burn/lock block executes unconditionally: [1](#0-0) 

Only after the funds are gone does the event emit the unvalidated `recipient`: [2](#0-1) 

The same ordering flaw exists in `initTransfer1155`: [3](#0-2) 

And in the Starknet gateway — token burn/lock at lines 300–307, event emission at lines 316–330, with no recipient check anywhere: [4](#0-3) 

The NEAR side relies **exclusively** on the emitted event to reconstruct the transfer. The `evm/CLAUDE.md` security invariant confirms this: [5](#0-4) 

If the `recipient` string is not a parseable `OmniAddress` (empty, whitespace-only, a hex EVM address supplied by mistake, or any other malformed value), the prover will fail to decode it, `fin_transfer_callback` will panic, and the transfer will never be finalized: [6](#0-5) 

For bridged tokens burned via `BridgeToken.burn`, there is no on-chain recovery mechanism — the tokens are gone. For locked native ERC-20 tokens, recovery requires privileged admin action.

The Solana program carries the identical root cause and is already explicitly acknowledged in `solana/SECURITY.md`: [7](#0-6) 

The EVM and Starknet gateways have the same flaw with no equivalent acknowledgment or mitigation.

---

### Impact Explanation

A user who mistakenly supplies an invalid NEAR account ID — for example, pasting their own EVM wallet address into the `recipient` field — will have their bridged tokens permanently burned on EVM with no recovery. For burned bridged tokens (e.g., wNEAR on EVM), the loss is irreversible. This constitutes **permanent loss of bridged funds**, which falls within the Critical impact scope.

---

### Likelihood Explanation

Moderate. Cross-chain bridge UIs ask users to paste a destination-chain address. A user accustomed to EVM addresses may paste a hex address into the NEAR recipient field. There is no client-side or contract-level guard to catch this before the burn/lock executes. The scenario is realistic and has precedent in other bridge loss incidents. The Solana team's own acknowledgment of the same issue confirms the team considers it a real-world risk.

---

### Recommendation

Validate the `recipient` string **before** executing any token burn or lock:

1. Reject empty or whitespace-only strings.
2. Validate that the string conforms to NEAR account ID rules (lowercase alphanumeric, dots, underscores, hyphens; max 64 characters; no leading/trailing dots or double

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-412)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-480)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
```

**File:** starknet/src/omni_bridge.cairo (L300-330)
```text
            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```

**File:** evm/CLAUDE.md (L33-33)
```markdown
- **Event completeness**: `InitTransfer` and `FinTransfer` events must contain every field needed to reconstruct the transfer. The NEAR side relies solely on these events — any missing or ambiguous field means lost funds or spoofable transfers. Fields must not be collapsible (e.g. two different transfers must never produce the same event data)
```

**File:** near/omni-bridge/src/lib.rs (L705-707)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
