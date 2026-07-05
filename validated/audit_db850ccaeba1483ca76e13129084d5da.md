### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain Weight Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` function always returns `Right` for every certificate, bypassing all cryptographic and protocol-level checks. The production `processCerts` path in `makePerasCertPoolWriterFromChainDB` uses this stub directly. Any unprivileged peer can therefore inject arbitrary Peras certificates that are accepted without verification, accumulating unbounded weight boosts on attacker-chosen blocks and causing chain selection to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` class defines a universal degenerate instance for all block types in `SupportsPeras.hs`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against