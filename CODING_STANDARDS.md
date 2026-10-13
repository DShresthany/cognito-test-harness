# Coding standards

## Cleanup

The current refresh token of a lineage comes back revoked, or the scenario stays red. An already-consumed refresh token may come back `invalid-refresh-token`. Global sign-out may come back `invalid-access-token` only after that current revoke succeeded.
