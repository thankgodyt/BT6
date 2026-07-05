### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Unauthorized Chain-Weight Manipulation and Round-Number Replay After Garbage Collection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate, performing zero cryptographic or protocol validation. This is the only implementation of `validatePerasCert