# Duck Detector Grant-Domain Defense — 2026-05-23

PRs analyzed:
- `eltavine/Duck-Detector-Refactoring#38` — grant-domain split + importKey retained narrative + timing tightening (commit `b610f8e`).
- `eltavine/Duck-Detector-Refactoring#43` — grant-domain Java/hidden/private staged probe + updateSubcomponent stale persistence (commit `99a9074`).

## Detection vectors (root causes)

### 1. Grant isolated/self-domain full-chain split (#38, expanded by #43)
Probe issues `IKeystoreService.grant(KeyDescriptor, granteeUid, accessVector)` against an alias whose owner-side `getKeyEntry(APP)` already returns our patched chain.

- Public path: `KeyStoreManager.grantKeyAccess()` (Android 16+).
- Hidden path: reflection on the same hidden Java API (Android 12-15).
- Private path: direct binder transact on `IKeystoreService.grant` via raw IBinder with reflective `KeyDescriptor` AIDL parcel (any Android 12+).

All three paths land on `IKeystoreService.grant`. We previously did not intercept that method, so the grant either:
- returned `KEY_NOT_FOUND` because real keystore2 has no record of the software-generated alias → classified as `ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN` (FAIL); or
- returned a real grantId pointing nowhere our intercept knows about, then the probe's `getKeyEntry(GRANT, grantId)` either failed or returned a different chain than `getKeyEntry(APP, alias)` → classified as `ISOLATED_CHAIN_SPLIT` / `SELF_CHAIN_SPLIT` (FAIL).

The probe's mapper escalates either kind to `DetectorStatus.danger()` regardless of the surrounding TEE verdict.

### 2. UpdateSubcomponent stale TEE response persistence (#43)
Probe generates an attested key, then `setKeyEntry(existingPrivateKey, [markerCert])` which AOSP routes through `IKeystoreService.updateSubcomponent`. After update, two `getKeyEntry` reads check whether any pre-update certificate fingerprint is still present.

We already mutate the in-memory `KeyEntryResponse.metadata.certificate/certificateChain` correctly, so the basic readback returns the marker leaf. But `KeyMintSecurityLevelInterceptor.patchedChains[keyId]` retained the prior chain — defensive eviction is the right hardening.

## Defensive design

The contract we offer software keys is now:

> For any software-generated owner key, `getKeyEntry(APP, alias)`, `getKeyEntry(KEY_ID, nspace)`, and `getKeyEntry(GRANT, grantId)` return the same `KeyEntryResponse` — same metadata, same certificate, same chain.

This is a structural property; it survives renaming probe internals, adding more grant transports, switching between Java/hidden/private API, etc.

### Implementation

1. Intercept `IKeystoreService.grant` and `ungrant` (`Keystore2Interceptor.kt`).
   - When the descriptor refers to a software-generated owner alias, allocate a synthetic positive-63-bit `grantId`, store `grantId → (ownerKeyId, granteeUid)` in `KeyMintSecurityLevelInterceptor.softwareGrants`, and reply with `KeyDescriptor(domain=GRANT, nspace=grantId)`.
   - Otherwise, forward to real keystore2.
   - `ungrant` of a synthetic grant returns success and drops the entry; non-synthetic forwards.
2. Extend the existing `getKeyEntry` switch to honor `descriptor.domain == Domain.GRANT` by resolving via `softwareGrants` and returning the owner's `KeyEntryResponse`.
3. Plumb cleanup: `cleanupKeyData(keyId)` revokes every `softwareGrants` entry pointing at the owner; `clearAllGeneratedKeys` clears the whole map.
4. Defensive `updateSubcomponent` hardening: after updating `metadata.certificate/certificateChain`, evict the matching `patchedChains[keyId]` so the prior chain SHA-256 cannot be served again from any cached path.

### Files touched
- `app/src/main/java/org/matrix/TEESimulator/interception/keystore/Keystore2Interceptor.kt`
  - Added `GRANT_TRANSACTION` / `UNGRANT_TRANSACTION` constants and registered them in `interceptedCodes`.
  - Added `Domain.GRANT` branch in the `descriptor.alias == null` handler that calls `KeyMintSecurityLevelInterceptor.resolveGrantedResponse(grantId)`.
  - Added `code == GRANT_TRANSACTION || code == UNGRANT_TRANSACTION` dispatch in `onPreTransact`.
  - Added private `handleGrant`, `handleUngrant`, `resolveOwnerKeyId` methods.
  - Hardened `handleUpdateSubcomponent` to call `invalidatePatchedChainFor(ownerKeyId)`.
- `app/src/main/java/org/matrix/TEESimulator/interception/keystore/shim/KeyMintSecurityLevelInterceptor.kt`
  - Added `softwareGrants` map, `softwareGrantIdGen`, `SoftwareGrant` data class.
  - Added `findGeneratedOwnerKeyByKeyId`, `issueSoftwareGrant`, `revokeSoftwareGrantsForOwner`, `revokeSoftwareGrant`, `resolveGrantedResponse`, `invalidatePatchedChainFor`.
  - Wired `softwareGrants` cleanup into `cleanupKeyData` and `clearAllGeneratedKeys`.
- `gradle.properties`
  - Added `android.overridePathCheck=true` so the project compiles on the user's non-ASCII Windows path.

## Why this avoids the cat-and-mouse loop

The probe is detecting a structural inconsistency: any modification of `getKeyEntry(APP)` results that does not also propagate to `getKeyEntry(GRANT)` is an asymmetry future variants will keep finding. By making `softwareGrants` route every GRANT readback to the same `getGeneratedKeyResponse(ownerKeyId)` source, we close the family of detection vectors that key-grant-domain-divergence belongs to:

- Probe variants that compare ordered full chain → identical (same response object).
- Probe variants that compare leaf SHA-256 → identical.
- Probe variants that compare metadata fields (security level, KEY_ID nspace) → identical.
- Probe variants that exercise grant from a different binder (isolated process, hidden API, raw private binder) → all funnel through the same `IKeystoreService.grant` we now intercept.

The only remaining family of grant-domain probes that could still split would be ones that compare hardware vs. software keys. Those should not match because we only synthesize grants for software-generated owner aliases — calls referencing genuine hardware-backed keystore2 entries forward unchanged.

## Verification

The Android Gradle build cannot run on this machine because the SDK is not configured. Compilation must be verified on the next pass with a working SDK setup. The Kotlin source has been manually reviewed for:
- Signature compatibility with existing `BinderInterceptor.TransactionResult` usage.
- Correct AIDL parcel layout for the grant reply (single `KeyDescriptor` typed object, matching AOSP).
- Thread safety (all maps are `ConcurrentHashMap`).
- Cleanup paths (every `cleanupKeyData` caller now also drops grants).
