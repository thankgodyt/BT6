### Title
Unguarded `storage_unregister(force: true)` Allows Any nBTC Holder to Permanently Burn Tokens Without BTC Redemption — (`File: contracts/nbtc/src/lib.rs`)

---

### Summary

The nBTC token contract's `storage_unregister` implementation delegates unconditionally to the standard `near_contract_standards` `FungibleToken::internal_storage_unregister`. When called with `force: Some(true)`, this standard implementation burns any remaining nBTC balance of the caller's account. No override is present to block this path. Any nBTC holder can therefore destroy their own tokens outside the bridge's controlled withdrawal flow, permanently reducing nBTC total supply below the BTC amount locked in the bridge's UTXO set.

---

### Finding Description

The nBTC contract implements `StorageManagement` and forwards `storage_unregister` directly to the underlying `FungibleToken` helper:

```rust
// contracts/nbtc/src/lib.rs  lines 253-262
#[payable]
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    #[allow(unused_variables)]
    if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
        log!("Closed @{} with {}", account_id, balance);
        true
    } else {
        false
    }
}
```

The `near_contract_standards` `FungibleToken::internal_storage_unregister` behaviour when `force = Some(true)`:
1. Asserts `env::predecessor_account_id()` is the account being unregistered (so only the account owner can call it on themselves).
2. If the account's nBTC balance is non-zero, it calls `internal_withdraw` (reducing `total_supply`) and removes the account entry.
3. Returns the storage deposit to the caller.

This is the NEAR/NEP-141 structural analog to ERC-20's `burnFrom()`: a publicly reachable path that burns tokens without the bridge's authorization or any BTC redemption step.

The bridge's controlled burn path (`burn()` at lines 150-177) is correctly gated by `self.assert_bridge()`, which requires `env::predecessor_account_id() == self.bridge_id`. That guard is entirely bypassed by `storage_unregister`.

The bridge's documented invariant (CLAUDE.md lines 62-65) is:
> "Withdraw tokens already transferred: By the time `burn()` is called, tokens are in bridge balance via `ft_transfer`"
> "Only burn after BTC tx is verified on-chain"

`storage_unregister(force: true)` violates both conditions: it burns from the user's own balance (not the bridge balance) and requires no on-chain BTC verification.

---

### Impact Explanation

**Impact: Medium — permanent burning below backed supply.**

When a user calls `storage_unregister(force: Some(true))`:
- Their nBTC balance is destroyed and `ft_total_supply` is permanently reduced.
- The BTC that was deposited to mint those tokens remains locked in the bridge's UTXO set with no mechanism to recover or redistribute it.
- The bridge's 1:1 backing invariant (nBTC supply = BTC locked) is permanently broken downward.
- The user suffers an irreversible loss of funds: nBTC gone, BTC unredeemable.
- Repeated use by multiple holders compounds the supply/backing divergence over time.

This matches the allowed Medium impact: *"permanent burning below backed supply."*

---

### Likelihood Explanation

**Likelihood: Medium.**

- The call requires only a 1 yoctoNEAR attached deposit (standard `#[payable]` requirement for storage functions).
- No privileged role, no special knowledge, no operator cooperation is needed.
- Any registered nBTC holder can execute this against their own account at any time.
- A user who loses their private key or makes an error could accidentally trigger it; a malicious user could do so deliberately to grief the protocol's accounting.

---

### Recommendation

Override `storage_unregister` to reject any call that would burn a non-zero nBTC balance, mirroring the fix applied in the referenced audit (disabling the burn path):

```rust
#[payable]
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    // Disallow unregistration if the account still holds nBTC,
    // to prevent bypassing the bridge's controlled burn flow.
    let balance = self.token.ft_balance_of(account_id.clone());
    require!(balance.0 == 0, "Cannot unregister account with non-zero nBTC balance");
    if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
        log!("Closed @{} with {}", account_id, balance);
        true
    } else {
        false
    }
}
```

---

### Proof of Concept

1. Alice deposits BTC and receives 1 000 000 satoshi-units of nBTC via the normal bridge deposit flow.
2. Alice decides not to withdraw through the bridge. Instead she calls on the nBTC contract:
   ```
   nbtc.storage_unregister(force: true)  [attached: 1 yoctoNEAR]
   ```
3. `internal_storage_unregister(Some(true))` fires, calls `internal_withdraw` on Alice's account for 1 000 000 units, reducing `ft_total_supply` by 1 000 000.
4. Alice's storage deposit is returned to her.
5. The bridge's UTXO set still contains the BTC UTXO that backed Alice's nBTC. No withdrawal record exists; no BTC transaction is ever constructed. The BTC is permanently stranded.
6. `ft_total_supply` is now permanently lower than the sum of BTC UTXOs held by the bridge, breaking the 1:1 backing invariant with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/nbtc/src/lib.rs (L150-157)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
```

**File:** contracts/nbtc/src/lib.rs (L253-262)
```rust
    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
            log!("Closed @{} with {}", account_id, balance);
            true
        } else {
            false
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L331-334)
```rust
impl Contract {
    fn assert_bridge(&self) {
        require!(self.bridge_id == env::predecessor_account_id(), "Not Allow");
    }
```
