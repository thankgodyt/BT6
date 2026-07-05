### Title
Peras Vote Validation Checks Voter Existence But Omits BLS Signature Verification, Enabling Forged Votes to Manufacture Fraudulent Certificates and Manipulate Chain Selection - (`BlockSupportsPeras.hs`)

### Summary

The `validatePerasVote` function in the default `BlockSupportsPeras` instance checks only that the voter ID **exists** in the stake distribution, but never verifies the BLS signature binding the vote to a specific block and round. An unprivileged peer can forge votes for any block by reusing any voter ID present in the public stake distribution, accumulate enough forged stake to satisfy `votesReachQuorum`, cause `forgePerasCert` to produce a fraudulent certificate, and thereby inject a fake Peras boost into chain selection — making an honest node prefer a non-canonical chain.

---

### Finding Description

**Root cause — existence check without binding check**

The external report's bug