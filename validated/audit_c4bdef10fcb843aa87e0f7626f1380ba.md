### Title
Malicious ERC20 Token with Blacklist Permanently Freezes Bridged Funds on NEAR→EVM Path - (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

The Omni Bridge EVM contract accepts any arbitrary ERC20 token in `initTransfer` (no whitelist). A malicious token deployer can lock tokens in the bridge, sell the resulting NEAR-side bridge tokens to victims, then blacklist the EVM bridge contract address in the token. When victims attempt to bridge back (NEAR→EVM), their NEAR bridge tokens are burned irreversibly, but `finTransfer` on EVM always reverts because `safeTransfer` from the bridge to the recipient fails. There is no refund path on NEAR, resulting in permanent loss of bridged funds.

### Finding Description

The bridge is explicitly designed to be fully permissionless. `logMetadata` accepts any ERC20 address with no access control, and `initTransfer` accepts any token address with no whitelist check. [1](#0-0) 

In `finTransfer`, for native (non-bridge-deployed) ERC20 tokens, the contract calls:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount
);
``` [2](#0-1) 

If the token implements a blacklist on the `from` address and the attacker blacklists the bridge contract itself, this `safeTransfer` (which sends FROM the bridge TO the recipient) will always revert. Because the entire `finTransfer` transaction reverts, the `destinationNonce` is not permanently consumed. However, on the NEAR side, the bridge tokens were already burned in `init_transfer_internal` before `finTransfer` was ever called: [3](#0-2) 

There is no `cancel_transfer` or refund function in the NEAR bridge contract. The `pending_transfers` map retains the entry indefinitely, but no code path allows the user to recover the burned tokens. [4](#0-3) 

### Impact Explanation

Permanent freezing of bridged funds. Victims' NEAR-side bridge tokens are burned with no recovery path, and the corresponding EVM-side tokens remain locked in the bridge contract forever. This matches the critical impact category: permanent freezing of bridged funds across NEAR and EVM.

### Likelihood Explanation

The attack requires only:
1. Deploying a malicious ERC20 with a blacklist (trivial, no permission needed)
2. Calling `logMetadata` (permissionless, confirmed by design)
3. Calling `initTransfer` to lock tokens and receive NEAR bridge tokens
4. Selling NEAR bridge tokens to victims (e.g., via DEX)
5. Calling `setBlacklist(bridgeAddress)` on the malicious token

Steps 1–5 are all unprivileged and require no admin access. The attacker profits by selling worthless NEAR bridge tokens backed by an unwithdrawable EVM position.

### Recommendation

Implement an explicit token whitelist (admin-controlled allowlist of ERC20 addresses permitted in `initTransfer`). Alternatively, wrap the `safeTransfer` call in `finTransfer` in a try/catch and emit a `FailedFinTransfer` event that the NEAR side can use to trigger a refund of the burned tokens.

### Proof of Concept

**Attack flow:**

1. Attacker deploys `MaliciousToken` (ERC20 with `_beforeTokenTransfer` that reverts if `from == blacklist`)
2. Attacker calls `OmniBridge.logMetadata(maliciousToken)` — succeeds, no access control: [5](#0-4) 

3. Attacker calls `OmniBridge.initTransfer(maliciousToken, amount, ...)` — tokens locked in bridge, `InitTransfer` event emitted: [6](#0-5) 

4. NEAR relayer finalizes the EVM→NEAR leg; NEAR bridge tokens minted to attacker. Attacker sells them to victim.

5. Attacker calls `maliciousToken.setBlacklist(bridgeAddress)`.

6. Victim calls `ft_transfer_call` on NEAR bridge token → `ft_on_transfer` → `init_transfer_internal` → **tokens burned on NEAR**: [7](#0-6) 

7. Relayer calls `OmniBridge.finTransfer(sig, payload)` on EVM. Execution reaches:
```solidity
IERC20(maliciousToken).safeTransfer(victim, amount); // REVERTS: bridge is blacklisted
``` [8](#0-7) 

8. Transaction reverts. Nonce not consumed. Victim's NEAR tokens are gone. EVM tokens remain locked in bridge. No refund path exists. Funds permanently frozen.

### Citations

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-412)
```text
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```
