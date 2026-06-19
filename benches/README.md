# Benchmarks

KDF / unlock timing (constraint **C22**) is implemented in `vault-core` (`crypto/tune.rs`) and
exposed as `vault tune`. The unit test `recommend_returns_valid_in_policy_params` exercises the
benchmark path in CI.

To measure on your machine:

```sh
vault tune
```

A dedicated `cargo bench` harness may land here later; until then, `vault tune` is the supported
interface.
