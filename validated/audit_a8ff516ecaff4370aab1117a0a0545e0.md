Looking at the H-1 vulnerability class — **check-then-normalize**: a value is validated against a threshold on its raw form, but the stored/used value is a normalized (floor-divided) version that can violate the check's intent — I need to find the same pattern in the NEAR Omni Bridge.

Let me trace the relevant code paths.