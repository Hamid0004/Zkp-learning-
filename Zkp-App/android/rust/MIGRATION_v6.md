# v6.0 Proof Migration (C3 + M1 + M4)

## What Changed

| Item | Before | After |
|---|---|---|
| Field encoding | 8-byte LE chunks (non-canonical risk) | 7-byte / 56-bit canonical chunks |
| Age calculation | Average-year arithmetic (±1 day drift) | Civil-calendar calculation |
| `PROOF_VERSION` | `"5.0"` | `"6.0"` |

## Cryptographic Impact

The field-encoding change affects Poseidon inputs derived through
`bytes_to_field_elements()`.

Affected derived values include:

- Merkle leaf hashes
- Merkle roots
- Nullifiers
- Salts
- `dg1_anchor`
- `hw_binding`
- `revocation_id`

The circuit digest also changes because the circuit/proof format has changed.

Therefore:

- v5.x proofs are incompatible with v6.0.
- v5.x verifier keys must not be used with v6.0 proofs.
- Verifiers must reject proofs whose version is not `"6.0"`.

## Migration Actions

- [ ] Purge stored roots, nullifiers, and Merkle trees from device storage
- [ ] Regenerate verifier keys from the v6.0 circuit
- [ ] Kotlin side: reject any proof whose version is not `"6.0"`
- [ ] Update server/verifier deployments before the mobile v6.0 release
- [ ] Verify end-to-end proof generation and verification after migration