# DICE Material Import

The RKP Workbench accepts an existing DICE chain and its matching signing material.
It does not collect material from a device or patch firmware. An existing CSR is only
an optional input to the separate offline `rkp verify` / identity matching tools.

## Workflow

1. Place material files in a private device directory. The WebUI takes file paths;
   secret bytes are never uploaded through its shell transport or browser storage.
2. Select **Import DICE materials** and run local validation. Chain signatures, the
   signing-key match and source trust are separate facts. Internal signature validity
   does not establish a manufacturer's trust anchor or server registration.
3. Supply explicit device and issuance configuration. Missing fields produce an error;
   the import path does not borrow generic identity values or the saved profile.
4. Select online issuance. Each invocation obtains a new challenge, generates a new
   P-256 attestation key and signs a new CSR v3 with the imported leaf identity.
5. All returned chains are considered for a unique public-key match. Certificate
   signatures, validity, chain relationships and supported constraints are checked.
   The attestation key certificate must be a CA allowed to sign certificates; ancestor
   path-length constraints must also permit the later application certificate.
   Only a complete verified result is exported. Installation is a separate operation.

```sh
duckd rkp import validate --bundle /private/material.json
duckd rkp import diagnose --bundle /private/material.json
duckd rkp import issue --bundle /private/material.json

# raw CBOR chain with an independent signing description and configuration
duckd rkp import validate --chain /private/chain.cbor --signing /private/signing.json
duckd rkp import issue --chain /private/chain.cbor --signing /private/signing.json --config /private/config.json
```

`diagnose` makes no network requests and writes `diagnostic-only.cbor`. Its ephemeral
attestation key is discarded, so this file cannot be used later to obtain an exportable
keybox. `issue` always constructs a new request. No old challenge, signature or pending
attestation key is reused. Requests use CSR payload version 3 / AuthenticatedRequest
version 1 and do not require legacy EEK or ProtectedData construction.

## Version 1 JSON contract

The package is UTF-8 JSON. Unknown or duplicate fields, unsupported versions, truncated
input and trailing data are rejected. Hex fields encode bytes and have no `0x` prefix.
Placeholders below must be replaced locally; they are not usable signing materials.

```json
{
  "version": 1,
  "dice_chain_hex": "<the complete original CBOR chain, hex encoded>",
  "signing": {
    "kind": "ed25519-seed",
    "bytes_hex": "<32 bytes as 64 hexadecimal characters>"
  },
  "device": {
    "brand": "<actual brand>",
    "model": "<actual model>",
    "device": "<actual device>",
    "product": "<actual product>",
    "manufacturer": "<actual manufacturer>",
    "fused": 1,
    "vb_state": "green",
    "os_version": "<actual OS version>",
    "security_level": "tee",
    "bootloader_state": "locked",
    "boot_patch_level": 20261001,
    "system_patch_level": 202610,
    "vendor_patch_level": 20261001
  },
  "issuance": {
    "fingerprint": "<actual build fingerprint>",
    "server_url": "https://remoteprovisioning.googleapis.com/v1",
    "protocol": "v3"
  }
}
```

`device` and `issuance` may be absent for validation. Diagnostic CSR construction requires
`device`; online issuance also requires `issuance`. Optional `device.vbmeta_digest` is a
32-byte hex digest. Experimental `dice_issuer` and `dice_subject` fields may be omitted;
the imported chain supplies its own identities. Optional `uds_certs_hex` encodes a complete
CBOR map from signer names
to arrays of DER certificate byte strings in root-to-leaf order. Every supplied path is
verified and its leaf public key must match the DICE root. Empty UDS maps are allowed.
CDI_Seal is not required and is not stored. Unsupported extra secret fields are rejected.

The split signing JSON contains just the `signing` object's fields. A split configuration
file contains optional `device`, `issuance` and `uds_certs_hex` fields. A bundle can also
use `--config` to supply missing sections; providing the same section in both places is
a configuration conflict and never silently replaces material.

Host-only server URLs use `/v1`; trailing slashes are removed before RPC methods are
appended. HTTPS and endpoint safety checks still apply.

Limits: 256 KiB per file, 2–32 DICE chain items (including the root), 16 nesting levels,
64 entries per container. Input files must be regular files; Unix symlinks and special
files are rejected. Imported DICE chain bytes, protected headers, signed payloads and
signatures are preserved. Supported optional COSE metadata is validated; unsupported
critical headers are rejected.
The assembled CSR also has a 256 KiB limit. With complete configuration, validation
builds a local request using the maximum supported challenge length before reporting
issuance readiness; this preflight makes no network requests and saves no key material.

## Supported signing combinations

| Material `kind` | Input | Required `derivation` | Signature |
| --- | --- | --- | --- |
| `ed25519-seed` | 32-byte Ed25519 signing seed | absent or `direct` | Ed25519 |
| `p256-scalar` | valid 32-byte big-endian private scalar | absent or `none` | ES256 |
| `p384-scalar` | valid 48-byte big-endian private scalar | absent or `none` | ES384 |
| `p256-seed` | 32-byte legacy workbench seed | `duck-rkp-legacy-mod-n-minus-1-plus-1` | ES256 |
| `cdi-attest` | 32-byte CDI_Attest | `open-dice-hkdf-sha512-ed25519` | Ed25519 |
| `auto` | one candidate byte string | absent or `auto` | unique supported match only |

Explicit kinds may select `derivation: "auto"` only within that kind's supported scheme.
Automatic identification tries this finite set and succeeds only for one leaf public-key
match. It never guesses from a vendor name, byte length or the root curve. Signing
algorithms may differ between chain levels; Ed25519, P-256 and P-384 verification is
supported. CDI_Attest, a signing seed and a final private scalar are distinct inputs.
Expanded Ed25519 private material, other CDI derivations, other P-384 seed mappings,
legacy CSR v1 issuance, arbitrary vendor capture packages and device acquisition are
unsupported. The package format above is the supported structured adapter; no external
capture-format compatibility is claimed.

The CDI scheme follows the default HKDF-SHA512 / Ed25519 construction in the
[Open Profile for DICE](https://android.googlesource.com/platform/external/open-dice/+/refs/heads/main/docs/specification.md),
with an independent official test vector. It is not a universal device derivation.
Request structure follows AOSP's
[CSR v3 CDDL](https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/rkp/aidl/android/hardware/security/keymint/generateCertificateRequestV2.cddl).

## Results and recovery

CLI JSON reports `validated`, `diagnostic` or `exported` stages. Export success requires
`server_accepted`, `certificates_verified` and `keybox_exported`. Reports contain no
private key or keybox XML. Returned certificate roots are checked for internal consistency;
external root trust and revocation are not established by these checks.

Network errors before signing submission, explicit HTTP rejection and an unknown
submission outcome are errors. No automatic signing retry occurs. In particular, an
unknown submission outcome may already have consumed server quota; inspect it before
starting another online operation. Input or configuration changes clear UI results.
An HTTP success response with an unreadable, oversized or malformed certificate result
also has an unknown submission outcome and must not be retried automatically.

Artifacts use new private run directories (0700) and files (0600). XML private-key,
certificate order, counts and DeviceID are checked before and after atomic publication.
Failures clean up temporary output and do not replace profiles or an installed keybox.
The experimental profile commands remain available for compatibility:
`rkp provision`, `rkp provision --offline`, `rkp keybox`; their old seed mapping is retained.
Experimental offline diagnostics require signing material and device information, honor
the requested key count within the supported range of 1–16, and do not require an online
fingerprint or server endpoint.

## Verification status

Automated tests use synthetic keys and a loopback server, including a complete imported
chain → new CSR → matching server certificate → keybox flow. Offline checks cover material
parsing and matching, request binding, certificate validation and export readback. Production server acceptance:
**0 observed**. Production keybox exports from real imported material: **0 observed**.
No real-material issuance or physical-device validation has been performed for this
path. These counts describe this implementation session, not expected server acceptance.
