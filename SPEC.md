# hpcs-grep11-go — Module Specification

> **Module:** `github.com/IBM-Cloud/hpcs-grep11-go/v2`
> **Go version:** `1.27.2` (minimum; resolved by `go mod tidy`)
> **Version:** v2

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Architecture Overview](#2-architecture-overview)
3. [Package Reference](#3-package-reference)
   - [pkg/authorize](#31-pkgauthorize)
   - [pkg/ep11](#32-pkgep11)
   - [pkg/grpc](#33-pkggrpc)
   - [pkg/util](#34-pkgutil)
   - [examples](#35-examples)
4. [gRPC Service — Crypto](#4-grpc-service--crypto)
5. [Key Blobs](#5-key-blobs)
6. [Mechanisms & Parameters](#6-mechanisms--parameters)
7. [Cipher Flows](#7-cipher-flows)
8. [IAM Authentication](#8-iam-authentication)
9. [TLS / mTLS Support](#9-tls--mtls-support)
10. [Dependencies](#10-dependencies)
11. [Environment Variables](#11-environment-variables)
12. [Error Handling](#12-error-handling)
13. [Known Limitations](#13-known-limitations)
14. [Change Log](#14-change-log)

---

## 1. Purpose

`hpcs-grep11-go` is the official IBM Cloud Go client library for interacting with
**IBM Cloud Hyper Protect Crypto Services (HPCS)** via the
**Enterprise PKCS #11 over gRPC (GREP11)** protocol.

It provides:
- A generated gRPC/protobuf client for all GREP11 Crypto service RPCs.
- IAM bearer-token lifecycle management (acquire, cache, refresh).
- Helper types and functions for building EP11 key templates, decoding public
  keys (ECDSA, Ed25519, RSA, DH), and converting gRPC errors to typed EP11
  status codes.
- A `crypto.Signer` adapter (`EP11PrivateKey`) enabling EP11-backed private keys
  to be used transparently in `crypto/tls`.
- Comprehensive runnable examples covering every major PKCS #11 operation.

The library does **not** include a server implementation. It is purely a client SDK.

---

## 2. Architecture Overview

```
 ┌─────────────────────────────────────────────────────────┐
 │                  Caller / Application                   │
 └────────────────────────────┬────────────────────────────┘
                              │ imports
              ┌───────────────▼───────────────┐
              │         pkg/util              │
              │  GetCryptoClient()            │
              │  AttributeMap()               │
              │  GetPubKey() / GetECPoint()   │
              │  Convert() (error helper)     │
              │  GenerateIV()                 │
              │  EP11PrivateKey (Signer)       │
              └───────┬───────────────┬───────┘
                      │               │
          ┌───────────▼───┐   ┌───────▼──────────┐
          │  pkg/authorize │   │    pkg/ep11       │
          │  IAMPerRPC     │   │  header_consts.go │
          │  Credentials   │   │  CKM_*, CKA_*,   │
          │  (token mgmt)  │   │  CKR_* constants  │
          └───────┬───────┘   └──────────────────┘
                  │ grpc.PerRPCCredentials
          ┌───────▼───────────────────────┐
          │         pkg/grpc              │
          │  CryptoClient (generated)     │
          │  All request/response protos  │
          │  Grep11Error proto            │
          └───────────────┬───────────────┘
                          │ TLS gRPC (port 443)
          ┌───────────────▼───────────────┐
          │    IBM Cloud HPCS Instance    │
          │  (EP11 HSM — CEX7 / CEX8)    │
          └───────────────────────────────┘
```

See [`arch_diagram.drawio`](arch_diagram.drawio) for the full interactive diagram.

---

## 3. Package Reference

### 3.1 `pkg/authorize`

Provides IBM Cloud IAM authentication for gRPC connections.

#### Types

| Type | Description |
|---|---|
| `IAMPerRPCCredentials` | Implements `grpc.PerRPCCredentials`. Holds an API key, IAM endpoint URL, cached access token, and expiry time. Token refresh is thread-safe via `sync.Mutex`. |

#### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `APIKey` | `string` | Yes (or `AccessToken`) | IBM Cloud IAM API key |
| `Endpoint` | `string` | Yes (or `AccessToken`) | IAM endpoint, e.g. `https://iam.cloud.ibm.com` |
| `AccessToken` | `string` | Alternative | Pre-obtained bearer token (skips automatic refresh) |

#### Methods

| Method | Signature | Description |
|---|---|---|
| `GetRequestMetadata` | `(ctx, uri...) (map[string]string, error)` | Called by gRPC per-RPC; refreshes token when expired |
| `RequireTransportSecurity` | `() bool` | Always returns `true` — TLS is mandatory |

#### Token Refresh Behaviour

- Tokens are cached until `ExpiresIn - 60` seconds from acquisition.
- Double-checked locking ensures only one goroutine refreshes at a time.
- HTTP response status is validated (`200 OK` required); non-200 returns an error immediately.
- Uses `http.NewRequestWithContext` to respect caller context cancellations.

---

### 3.2 `pkg/ep11`

Generated constants file (`header_consts.go`) — do not edit manually.

Exports three categories of PKCS #11 constants:

| Prefix | Type | Example |
|---|---|---|
| `CKM_` | `Mechanism` | `CKM_AES_KEY_GEN`, `CKM_ECDSA`, `CKM_RSA_PKCS` |
| `CKA_` | `Attribute` | `CKA_ENCRYPT`, `CKA_SIGN`, `CKA_VALUE_LEN` |
| `CKR_` | Return code | `CKR_OK`, `CKR_SIGNATURE_INVALID`, `CKR_GENERAL_ERROR` |

Also exports:

| Symbol | Type | Description |
|---|---|---|
| `EP11Attributes` | `map[Attribute]interface{}` | Convenience type for key templates |
| `AES_BLOCK_SIZE` | `int` | 16 |
| `DES_BLOCK_SIZE` | `int` | 8 |

---

### 3.3 `pkg/grpc`

Auto-generated from `protos/server.proto` and `protos/errors.proto` using
`protoc` + `gogofast` plugin.

**Do not edit directly** — regenerate with `make build-protos`.

Key generated types:

| Type | Description |
|---|---|
| `CryptoClient` | gRPC client interface for all 50+ Crypto RPCs |
| `KeyBlob` | Wraps raw EP11 key bytes, attributes, and metadata |
| `Mechanism` | Carries mechanism ID and optional typed parameter |
| `Grep11Error` | Structured EP11 error with `Code`, `Detail`, and `Retry` fields |
| `RSAOAEPParm` | OAEP mechanism parameters |
| `RSAPSSParm` | PSS mechanism parameters |
| `ECDH1DeriveParm` | ECDH key derivation parameters |
| `BTCDeriveParm` | BIP32/SLIP10 derivation parameters |

---

### 3.4 `pkg/util`

Application-level helpers. Safe for direct use in production code.

#### Functions

| Function | Signature | Description |
|---|---|---|
| `GetCryptoClient` | `(*ClientConfig) (CryptoClient, *grpc.ClientConn, error)` | Creates a gRPC connection and returns a typed Crypto client |
| `AttributeMap` | `(EP11Attributes) map[Attribute]*AttributeValue` | Converts a Go-native attribute map to protobuf format |
| `AttributeValue` | `(interface{}) *AttributeValue` | Converts a single Go value to protobuf `AttributeValue` |
| `GetAttributeByteValue` | `(interface{}) ([]byte, error)` | Returns the byte-slice encoding of an attribute value |
| `GetPubKey` | `([]byte) (crypto.PublicKey, asn1.OID, error)` | Parses an SPKI blob into a Go public key (`ecdsa`, `ed25519`, or `rsa`) |
| `GetECPointFromSPKI` | `([]byte) ([]byte, error)` | Extracts the raw EC point coordinates from an SPKI |
| `GetNamedCurveFromOID` | `(asn1.OID) elliptic.Curve` | Maps an OID to a stdlib elliptic curve |
| `GetSignMechanismFromOID` | `(asn1.OID) (Mechanism, error)` | Returns the signing mechanism for an OID |
| `Convert` | `(error) (bool, *Grep11Error)` | Unwraps a gRPC status error into a typed `Grep11Error` |
| `GenerateIV` | `(CryptoClient, BlockType) ([]byte, error)` | Requests random IV bytes from the remote HSM |
| `MechanismExists` | `(CryptoClient, Mechanism) bool` | Queries the HSM to check if a mechanism is supported |
| `PrintAttributes` | `(map[Attribute]*AttributeValue)` | Pretty-prints key attribute table to stdout |
| `Pause` | `(chan string, chan os.Signal, string)` | Blocks goroutine until SIGINT/SIGTERM |
| `SetMechParm` | `([]byte) *Mechanism_ParameterB` | Wraps a byte slice as a mechanism parameter |

#### Types

| Type | Description |
|---|---|
| `ClientConfig` | Holds `Address`, `APIKey`, `IAMEndpoint`, `DialOpts` for `GetCryptoClient` |
| `EP11PrivateKey` | `crypto.Signer` backed by an HSM key blob; used in `tls.Certificate` |
| `BlockType` | `int` alias — `AESBlkSize` (16) or `DESBlkSize` (8) |

#### OID Constants

All standard and extended curve OIDs are exported as `asn1.ObjectIdentifier` variables:

- Standard NIST: `OIDNamedCurveP224/256/384/521`
- Koblitz: `OIDNamedCurveSecp256k1`
- Montgomery/Edwards: `OIDNamedCurveX25519`, `OIDNamedCurveX448`, `OIDNamedCurveED25519`, `OIDNamedCurveED448`
- Brainpool (regular + twisted): `OIDBrainpoolP160r1` … `OIDBrainpoolP384t1`
- Post-quantum: `OIDDilithiumHigh`, `OIDDilithiumR3*`, `OIDKyberR2*`
- BLS12-381: `OIDBLS12_381ET`
- Public key types: `OIDECPublicKey`, `OIDRSAPublicKey`, `OIDDSAPublicKey`, `OIDDHPublicKey`

---

### 3.5 `examples`

Runnable Go test examples (package `examples`, file suffix `_test.go`).
Each example connects to a live HPCS instance and is skipped if the required
mechanism is absent from the configured HSM card.

| File | Operations covered |
|---|---|
| `keyGeneration_test.go` | Generic, AES, DES3, RSA, EC, BLS12-381, Kyber, DH, DSA |
| `encryptDecrypt_test.go` | AES/DES3/RSA encrypt & decrypt (ESP / PSP / PMP flows) |
| `signVerify_test.go` | AES HMAC, RSA, RSA-PSS, DSA, ECDSA sign & verify |
| `wrapUnwrap_test.go` | AES-with-RSA wrap/unwrap, attribute-bound keys, import/export |
| `derive_test.go` | ECDH key derivation |
| `digest_test.go` | SHA-1/224/256/384/512 digest (single & multi-part) |
| `generateRandomBytes_test.go` | HSM-backed TRNG |
| `mechanismInfo_test.go` | Mechanism list & info queries |
| `keyRotation_test.go` | ReencryptSingle (key rotation) |
| `reencryptSingle_test.go` | ReencryptSingle detailed flow |
| `bip32_test.go` | BIP32 hierarchical deterministic key derivation |
| `slip10_test.go` | SLIP10 key derivation |
| `schnorr_test.go` | Schnorr signatures |
| `ed25519_test.go` | Ed25519 sign & verify |
| `bls_test.go` | BLS12-381 sign & verify (CEX7/CEX8 only) |
| `dilithium_test.go` | Dilithium post-quantum sign & verify (CEX7/CEX8 only) |
| `kyber_test.go` | Kyber KEM encapsulate & decapsulate (CEX7/CEX8 only) |
| `tls_test.go` | mTLS using EP11-backed ECDSA private key via `crypto.Signer` |

---

## 4. gRPC Service — Crypto

Defined in `protos/server.proto`. The service exposes the following RPC groups:

| Group | RPCs |
|---|---|
| **Random** | `GenerateRandom` |
| **Digest** | `DigestInit`, `Digest`, `DigestUpdate`, `DigestKey`, `DigestFinal`, `DigestSingle` |
| **Encrypt** | `EncryptInit`, `EncryptUpdate`, `EncryptFinal`, `EncryptSingle` |
| **Decrypt** | `DecryptInit`, `DecryptUpdate`, `DecryptFinal`, `DecryptSingle` |
| **Sign** | `SignInit`, `Sign`, `SignUpdate`, `SignFinal`, `SignSingle` |
| **Verify** | `VerifyInit`, `Verify`, `VerifyUpdate`, `VerifyFinal`, `VerifySingle` |
| **Key Gen** | `GenerateKey`, `GenerateKeyPair` |
| **Key Mgmt** | `WrapKey`, `UnwrapKey`, `RewrapKeyBlob`, `DeriveKey` |
| **HSM Info** | `GetMechanismList`, `GetMechanismInfo`, `GetAttributeValue`, `SetAttributeValue` |
| **Re-encrypt** | `ReencryptSingle` |

Transport: TLS 1.2+ mandatory. Default port: **443**.

---

## 5. Key Blobs

All key creation operations return EP11 **key blobs** — opaque encrypted byte
slices managed by the HSM. They must be persisted (e.g., database) by the caller
if they are needed beyond the current session.

```
KeyBlob {
  KeyBlobID  []byte                      // internal server use only
  Version    int64                       // internal server use only
  TxID       []byte                      // internal server use only
  Attributes map[ep11.Attribute]Value    // PKCS#11 attribute set
  KeyBlobs   [][]byte                    // KeyBlobs[0] = raw EP11 blob
}
```

- **Private key blobs** are encrypted by the HSM's master key and opaque to the client.
- **Public key blobs** are returned in SPKI (SubjectPublicKeyInfo) DER format — parseable by `util.GetPubKey`.
- All non-generation operations require the `KeyBlob` message form, **not** the raw `bytes` fields.

---

## 6. Mechanisms & Parameters

All mechanism identifiers follow the PKCS #11 naming convention (`CKM_*`).
Some mechanisms require a typed parameter in the `Mechanism.Parameter` oneof:

| Mechanism family | Parameter type | Protobuf message |
|---|---|---|
| RSA-OAEP | Hash + MGF | `RSAOAEPParm` |
| RSA-PSS | Hash + MGF | `RSAPSSParm` |
| ECDH derive | KDF + shared data | `ECDH1DeriveParm` |
| BTC/BIP32 derive | Path + type | `BTCDeriveParm` |
| Schnorr | Curve + hash | `ECSGParm` |
| Kyber KEM | Mode | `KyberKEMParm` |
| EC Aggregate | Mode | `ECAGGParm` |
| All others | Raw bytes | `ParameterB` |

---

## 7. Cipher Flows

GREP11 supports three calling-sequence flows for Encrypt, Decrypt, Digest, Sign, and Verify:

| Flow | Sub-operations | Use case |
|---|---|---|
| **ESP** (EP11 Single-Part) | `*Single()` only | Smallest round-trips; entire payload in one call |
| **PSP** (PKCS#11 Single-Part) | `*Init()` → `*()` | Standard single-part; full payload known upfront |
| **PMP** (PKCS#11 Multi-Part) | `*Init()` → `*Update()` × N → `*Final()` | Streaming / chunked data |

---

## 8. IAM Authentication

```
Client                    IAM Endpoint                  HPCS gRPC
  │                            │                             │
  │── POST /identity/token ───▶│                             │
  │   grant_type=apikey        │                             │
  │◀── {access_token, exp} ────│                             │
  │                            │                             │
  │─── RPC call ───────────────────────────────────────────▶│
  │    Authorization: Bearer <token>                         │
  │◀── RPC response ────────────────────────────────────────│
```

- Token is obtained once and cached in `IAMPerRPCCredentials.AccessToken`.
- Expiry is set to `expires_in - 60` seconds as a safety margin.
- All token refreshes are serialised with `sync.Mutex`; concurrent gRPC calls
  that race on expiry will only produce one HTTP request to IAM.

---

## 9. TLS / mTLS Support

Standard TLS (server-authenticated) is always required:

```go
grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
```

For mutual TLS (mTLS), the library provides `util.EP11PrivateKey` which implements
`crypto.Signer` so that an HSM-backed key blob can be used as the private key
in a `tls.Certificate`. This enables scenarios where the TLS client certificate
private key never leaves the HSM.

```go
signer, _ := util.NewEP11Signer(cryptoClient, privBlob, pubBlob)
tlsCert := tls.Certificate{
    Certificate: [][]byte{certDER},
    PrivateKey:  signer,   // crypto.Signer backed by HSM
}
```

---

## 10. Dependencies

| Module | Version | Role |
|---|---|---|
| `google.golang.org/grpc` | `v1.84.0` | gRPC transport |
| `google.golang.org/protobuf` | `v1.36.12` | Protobuf runtime |
| `github.com/golang/protobuf` | `v1.5.4` | Legacy proto wrapper (gogo compat) |
| `github.com/gogo/protobuf` | `v1.3.2` | EP11 proto codegen (gogofast) |
| `github.com/btcsuite/btcd/btcec/v2` | `v2.5.0` | secp256k1 key parsing (BIP32/Schnorr) |
| `github.com/Zilliqa/gozilliqa-sdk/v3` | `v3.0.0-20230120` | Zilliqa BIP32 derive helper |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | `v4.4.1` | secp256k1 low-level ops (indirect) |
| `golang.org/x/net` | `v0.60.0` | HTTP/2 transport (indirect, gRPC dep) |
| `golang.org/x/sys` | `v0.48.0` | OS syscall shims (indirect) |
| `golang.org/x/text` | `v0.42.0` | Unicode utilities (indirect) |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20261005` | gRPC status types (indirect) |

---

## 11. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GREP11_ADDRESS` | Yes | `<grep11_server_address>:<port>` | Full EP11 endpoint URL including port |
| `GREP11_APIKEY` | Yes | `<ibm_cloud_apikey>` | IBM Cloud IAM API key |
| `GREP11_IAMENDPOINT` | No | `https://iam.cloud.ibm.com` | Override IAM token endpoint |
| `GREP11_LOCAL` | No | _(unset)_ | When set, connects without TLS (local/dev only) |

---

## 12. Error Handling

gRPC errors from HPCS are wrapped as `Grep11Error` proto messages embedded
in the gRPC status detail. Use `util.Convert()` to unpack:

```go
_, err := cryptoClient.VerifySingle(ctx, req)
if ok, ep11Err := util.Convert(err); !ok {
    switch ep11Err.Code {
    case ep11.CKR_SIGNATURE_INVALID:
        // handle bad signature
    case ep11.CKR_KEY_HANDLE_INVALID:
        // handle stale key blob
    default:
        log.Printf("EP11 error %d: %s (retry=%v)", ep11Err.Code, ep11Err.Detail, ep11Err.Retry)
    }
}
```

`Grep11Error.Retry` is `true` for transient HSM errors that may succeed on retry.

---

## 13. Known Limitations

| # | Limitation |
|---|---|
| 1 | **BLS12-381, Dilithium, Kyber** operations require **CEX7 or CEX8** Crypto Express cards. Tests are automatically skipped on CEX6 and earlier. |
| 2 | **`golang/protobuf` v1 wrapper** (`github.com/golang/protobuf`) is kept as a direct dependency because `gogo/protobuf` generated code calls `proto.RegisterType` from the v1 API. It cannot be removed until the protos are regenerated with the modern `google.golang.org/protobuf` plugin. |
| 3 | **RSA private key signing** via `EP11PrivateKey.Sign()` is not yet implemented (returns `"RSA public key is currently not supported"`) — only ECDSA is supported for mTLS. |
| 4 | The `RewrapKeyBlob` example is **skipped by default** and requires coordination with the HPCS instance administrator. |
| 5 | `Makefile build-protos` target requires `protoc` and `protoc-gen-gogofast` to be installed separately. |

---

## 14. Change Log

### v2 — current

| Date | Change |
|---|---|
| 2025-07 | Go toolchain: `1.25.0` → `1.27.2` (resolved by `go mod tidy` against grpc v1.84.0 requirement) |
| 2025-07 | `google.golang.org/grpc`: `v1.81.1` → **`v1.84.0`** |
| 2025-07 | `btcsuite/btcd/btcec/v2`: `v2.2.0` → **`v2.5.0`** |
| 2025-07 | `decred/dcrd/dcrec/secp256k1/v4`: `v4.0.1` → **`v4.4.1`** |
| 2025-07 | `golang.org/x/net`: `v0.55.0` → **`v0.60.0`** |
| 2025-07 | `golang.org/x/sys`: `v0.45.0` → **`v0.48.0`** |
| 2025-07 | `golang.org/x/text`: `v0.37.0` → **`v0.42.0`** |
| 2025-07 | `google.golang.org/protobuf`: `v1.36.11` → **`v1.36.12`** |
| 2025-07 | Replaced deprecated `grpc.Dial` → `grpc.NewClient` in `pkg/util/util.go` |
| 2025-07 | Replaced deprecated `grpc.WithInsecure()` → `insecure.NewCredentials()` in `examples/main.go` |
| 2025-07 | Removed deprecated `grpc.WithBlock()` from local dev dial options |
| 2025-07 | Fixed `defer resp.Body.Close()` ordering and added HTTP status check in `pkg/authorize/authorize.go` |
| 2025-07 | Replaced `http.NewRequest + WithContext` with `http.NewRequestWithContext` |
| 2025-07 | Fixed unchecked `binary.Write` error in `util.AttributeValue()` |
| 2025-07 | Removed unused `sync.RWMutex` package-level variable |
| 2025-07 | Simplified `Pause()` — removed labeled `break` + trailing naked `return` |
