Looking at the vulnerability class from the external report: a value is stored/accepted by one function without validation, but a later function rejects that same value with an explicit check, creating an unprocessable state that permanently locks funds.

Let me examine the NEAR bridge's `init_transfer` and `sign_transfer` functions for this pattern.