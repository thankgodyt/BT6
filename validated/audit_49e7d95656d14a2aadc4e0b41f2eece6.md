### Title
Detached `burn` Call in `safe_mint_callback` Failure Path Can Fail Silently, Enabling UTXO Re-use and Unauthorized Minting - (File: contracts/satoshi-bridge/src/btc_light_client/deposit.rs)

### Summary
In `safe_mint_callback`, when `safe_mint` returns 0 (the failure/refund path), the bridge fires a `burn` cross-contract call with `.detach()` and no callback. If that burn fails silently for any reason, the minted tokens remain in the bridge's balance unbacked by BTC, while the UTXO is simultaneously cleared from `verified_deposit_utxo`. Because the replay-guard is gone, the same UTXO can be re-submitted via `verify_deposit` or `safe_verify_deposit`, minting a