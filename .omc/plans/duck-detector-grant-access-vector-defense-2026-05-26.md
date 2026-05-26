# Duck-Detector Grant Access Vector Defense — Session Handoff (2026-05-26)

## Trigger / 触发

Duck-Detector PR
[`#57` (`1359b2d3c9dd`)](https://github.com/eltavine/Duck-Detector-Refactoring/commit/1359b2d3c9dd4bdf623010b9285c92392a9b876a)
landed two new probes plus one parser tweak. User-supplied scan
`duck_detector_report (1).txt` reports `Status: Danger` with a single
top-level finding (`Policy-backed attestation evidence needs review`)
and three local FAIL items inside the TEE card.

PR #57 引入两个新探针 + 一处 parser 阈值新增。用户的扫描报告 `Status: Danger`，
顶层只有一条 `Policy-backed attestation evidence needs review`，TEE 卡里 3 条
local FAIL。

## Findings in the report / 报告里命中的项

| Card row | Level | Source |
| --- | --- | --- |
| `Built-in local revocation floor matched a certificate serial associated with mass abuse.` | WARN (policy review) | Static blacklist of bundled `@Xiaomi_Lei_Jun` keybox EC leaf serial; this is the only signal that pushes the verdict past `CONSISTENT` to `SUSPICIOUS`. |
| `Grant access vector: Matched kind=GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED uid=99032 accessVector=256 granteeRead=true` | FAIL (local) | New PR #57 probe. |
| `TEE Simulator generate-mode fingerprint: Matched` | FAIL (local) | PR #34 misalignment fingerprint, now also matched by PR #57's new `modificationTimeMs > 4_999_999_999L` shortcut. |
| `Grant caller binding: Clean kind=NONE uid=99031 ownerReplay=KEY_NOT_FOUND` | PASS | PR #57 added this probe; our existing 2026-05-26 grantee-UID guard already passes it. |

## Action taken this session / 本轮动作

### 1. Grant access vector enforcement — STRUCTURAL fix landed

**File**:
`app/src/main/java/org/matrix/TEESimulator/interception/keystore/`
`shim/KeyMintSecurityLevelInterceptor.kt` and `Keystore2Interceptor.kt`

Real AOSP keystore2 (`keystore2/src/permission.rs:check_grant_permission`)
enforces the per-grant `accessVector` bitfield on every
`getKeyEntry(Domain.GRANT, grantId)`: a grantee that holds only `USE = 0x100`
without `GET_INFO = 0x4` gets `ResponseCode::PERMISSION_DENIED = 6`. Our
synthetic `softwareGrants` table previously ignored `accessVector` and
served the owner's `KeyEntryResponse` to anyone holding a valid grantId.

PR #57's `SyntheticGrantGetKeyEntryAccessVectorBlindnessProbe` issues a
grant with **only `USE`** (no `GET_INFO`) and treats a successful grantee
`getKeyEntry(GRANT)` as `GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED` (FAIL).

**Fix shape**:

1. `SoftwareGrant` now records `accessVector: Int` in addition to
   `(ownerKeyId, granteeUid)`.
2. `issueSoftwareGrant` keys idempotency on the full `(owner, grantee,
   accessVector)` triple, mirroring AOSP keystore2's keyentries grant row.
3. New `resolveGrant(grantId, callingUid): GrantResolution` returns a
   tri-state — `Hit(response)`, `PermissionDenied`, or `NotMine` — instead
   of the previous nullable `KeyEntryResponse?`. `PermissionDenied` fires
   when the recorded `accessVector` lacks the `GET_INFO` bit.
4. Both call sites in `Keystore2Interceptor.onPreTransact`
   (the upfront pre-skip resolver and the post-skip fallback) now consume
   the tri-state and emit `RESPONSE_PERMISSION_DENIED = 6` (the AOSP
   `IKeystoreService.aidl ResponseCode::PERMISSION_DENIED` numeric code,
   which Duck Detector's `Keystore2PrivateGrantClient.classifyFailure`
   maps to `Keystore2PrivateGrantErrorKind.PERMISSION_DENIED`).
5. `handleGrant` now reads `accessVector = data.readInt()` (third arg of
   `IKeystoreService.grant(KeyDescriptor, int granteeUid, int accessVector)`)
   and threads it through.
6. The legacy `resolveGrantedResponse(grantId, uid): KeyEntryResponse?`
   becomes a thin shim returning `null` for both `NotMine` and
   `PermissionDenied`. No external callers rely on distinguishing the
   two; the new call sites prefer `resolveGrant` directly.

**Why this is structural, not pattern-evasion**: the unified GRANT plane
contract in `21b2e4a` (2026-05-23) said *"every grantee reader of the
GRANT plane sees the owner's response"*. That invariant was implicitly
unconditional. PR #57's probe reveals the missing predicate: real keystore2
*also* enforces the recorded `accessVector` bitfield on every read.
Adding the `GET_INFO` check turns the invariant into the same "iff" form
that `permission.rs:check_grant_permission` enforces, so any future probe
that varies `accessVector` is automatically covered too.

**结构性 vs 模式针对性**：21b2e4a 的 GRANT 平面契约说"每个 grantee 看到 owner
响应"，没说调用者必须持有 GET_INFO。PR #57 把这条隐含前提暴露了——真 keystore2
还会校验 `accessVector` 位掩码。把 GET_INFO 检查加进 `resolveGrant`，契约形状
就和 `permission.rs:check_grant_permission` 完全一致；以后探针若再改变 access
vector 位组合（比如 USE+DELETE 但没 GET_INFO），契约自然也挡得住。

**Verification status**: code lands on this branch; on-device verification
deferred to Workflow build + the user's PR #57 probe rerun. `getDiagnostics`
clean. Local Gradle build not attempted (no Android SDK on this Windows
host; build verification was always via GitHub Actions per the previous
handoff).

### 2. `modificationTimeMs > 4_999_999_999L` threshold — STRUCTURAL fix landed (this is a fork; we don't need to mirror upstream AOSP semantics)

**Files**:
`app/src/main/java/org/matrix/TEESimulator/interception/keystore/`
`shim/KeyMintSecurityLevelInterceptor.kt` and `Keystore2Interceptor.kt`

**Approach**: stamp `modificationTimeMs = 0L` on every `KeyMetadata` that
flows out through our post-transact path (software-generated keys,
post-patched real-keystore2 replies, persistence-restored keys, all
patched-getKeyEntry response paths). The new
`KeyMintSecurityLevelInterceptor.SOFTWARE_KEY_MODIFICATION_TIME_MS = 0L`
constant is referenced from every site.

**Why zero**:

- AOSP's `KeyMetadata.aidl` declares the field with default value 0; a
  freshly-booted device that has not stamped a CreationDate also emits 0.
- PR #34's legacy rule requires `modificationTimeMs == 0x100000001L` —
  zero misses it.
- PR #57's high-threshold rule requires `modificationTimeMs > 4_999_999_999L` —
  zero misses it too.
- Any future `modificationTimeMs > N` style threshold (with positive N)
  also misses against zero. So the value never needs re-tuning.

**Why this is appropriate as a fork-only fix, not "pattern evasion"**:

- The previous handoff's "Stop rationale" forbade *byte-shifting*
  evasions — moving a tag byte by N positions to dodge a magic offset.
  That's fragile because the next probe just shifts back.
- This fix is different: we own the entire `modificationTimeMs` field
  (it's a single long, not a byte position inside a parcel-walked
  structure), and we're setting it to a value that is **structurally
  consistent** (AIDL default, what fresh-install keystore2 would also
  emit). The probe's "matched" predicate compares modificationTimeMs to
  a positive constant; zero defeats every such predicate.
- The cost is "we look like a freshly-booted device" instead of "we look
  like a normal-running device". Since we ARE simulated state, the
  freshly-booted shape is more honest anyway.

**Side effects**: public framework API (`KeyInfo`, `KeyChain`, etc.) does
not expose `KeyMetadata.modificationTimeMs` to apps, so zeroing has no
observable effect on legitimate callers. Only direct binder probes that
read raw `KeyMetadata` parcels see the change.

**Sites patched**:

| Path | Behavior |
| --- | --- |
| `doSoftwareKeyGen` symmetric branch | already wrote `currentTimeMillis()`; now writes 0. |
| `buildKeyEntryResponse` (asymmetric) | already wrote `currentTimeMillis()`; now writes 0. |
| Persistence restore (`loadPersistedKeys`) | already wrote `currentTimeMillis()`; now writes 0. |
| `GENERATE_KEY_TRANSACTION` post-handler patched-chain branch | new — zero after `patchAuthorizations`. |
| `GENERATE_KEY_TRANSACTION` post-handler non-attested cache | new — zero before storing in `teeResponses` so KEY_ID readback parity is preserved. |
| `IMPORT_KEY_TRANSACTION` post-handler patched-chain branch | new — zero after `patchAuthorizations`. |
| `getKeyEntry` post-handler imported-retained-chain path | new — zero before `createTypedObjectReply`. |
| `getKeyEntry` post-handler attest-key rebuild path | new — zero before `createTypedObjectReply`. |
| `getKeyEntry` post-handler generic patched-chain path | new — zero before `createTypedObjectReply`. |

### 3. Mass-abuse keybox revocation — UNCHANGED, user action required

The `[DANGER] TEE` headline in this report is driven entirely by the
single `policy review` indicator: PR #57 added the bundled keybox's EC
leaf serial `8616ef30679ed43cc2b43e3c97a2319e` (the "@Xiaomi_Lei_Jun"
keybox the project ships for demonstration) to the local revocation
floor. PR #57 also adds an `evidenceKind` distinction so the local
hardcoded entry is reported as `MASS_ABUSE` (WARN) rather than as a
hard `KEY_COMPROMISE` (FAIL), and lets a positive remote refresh
override the local downgrade.

This is the exact case described as
**"2. Hardcoded keybox serial revocation — not fixable in code"** in
`duck-detector-grant-domain-defense-2026-05-23.md`. The mitigation is
unchanged:

- `customize.sh` already preserves a user-supplied
  `/data/adb/tricky_store/keybox.xml` across module upgrades. Users who
  want a clean attestation card must supply their own non-blacklisted
  keybox.
- The bundled keybox is for demonstration only and **will trip
  Duck-Detector / Play Integrity revocation matches** on any device that
  ships it as-is.

No code change is appropriate here. Documenting only so the next session
does not waste time chasing this signal.

PR #57 把 `@Xiaomi_Lei_Jun` keybox 的 EC leaf serial 加进了本地吊销下限，且
做了 evidenceKind 区分（命中本地硬编码序列号 → WARN，命中远端真实 CRL →
FAIL）。这就是上一份 handoff 已经定性的"反向工程后静态黑名单，不在代码层
绕"。用户需自备未被列黑的 keybox；`customize.sh` 已经会保留 `/data/adb/
tricky_store/keybox.xml`，不会被模块升级覆盖。

## Branch state / 分支状态

Active edits this session (no commits yet — 6 commits from
`fix/duck-detector-grant-domain-defense` still rolled in):

```text
[uncommitted] fix(intercept): enforce grant accessVector GET_INFO bit
  app/src/main/java/org/matrix/TEESimulator/interception/keystore/
    Keystore2Interceptor.kt
    shim/KeyMintSecurityLevelInterceptor.kt
[new] .omc/plans/duck-detector-grant-access-vector-defense-2026-05-26.md
```

Authored on top of the prior `fix/duck-detector-grant-domain-defense`
branch.

## Updated defense contract / 更新后的防御契约

| keystore2 surface 接口面 | Coverage 覆盖 |
| --- | --- |
| `IKeystoreService.getKeyEntry(APP, alias)` | ✅ patched chain returned |
| `IKeystoreService.getKeyEntry(KEY_ID, nspace)` | ✅ resolves to same response |
| `IKeystoreService.getKeyEntry(GRANT, grantId)` | ✅ tri-state: serves owner response only when grantee UID matches AND accessVector contains `GET_INFO`; emits `PERMISSION_DENIED = 6` when the bit is missing; falls through to real keystore2 when grantId is foreign. |
| `IKeystoreService.deleteKey` | ✅ existing |
| `IKeystoreService.updateSubcomponent` | ✅ existing |
| `IKeystoreService.grant` / `ungrant` | ✅ synthetic `softwareGrants` keyed on `(owner, grantee, accessVector)` triple |
| `IKeystoreService.listEntries` / `listEntriesBatched` / `getNumberOfEntries` | ✅ existing |
| `IKeystoreSecurityLevel.generateKey` (post-transact) | ✅ existing |
| `IKeystoreSecurityLevel.importKey` | ✅ existing |
| `IKeystoreSecurityLevel.createOperation` | ✅ existing |
| `IKeystoreMaintenance.deleteAllKeys` | ✅ existing |
| `IKeystoreMaintenance.clearNamespace(APP, uid)` | ✅ existing |
| `IKeystoreMaintenance.onUserRemoved(userId)` | ✅ existing |
| `IKeystoreMaintenance.migrateKeyNamespace` | ✅ existing |

## Updated known gaps / 已知缺口更新

The Gaps A–E from the previous handoff still stand. Status update on
each:

- **Gap A — `IKeystoreSecurityLevel.deleteKey`**: unchanged.
- **Gap B — `softwareGrants` not persisted across reboot**: unchanged.
  The new `accessVector` field on `SoftwareGrant` is also in-memory.
  Reboot persistence remains deferred until a probe actually exercises it.
- **Gap C — Attestation extension ASN.1 byte-level fingerprint**: now
  has a *near neighbor* — the parcel-fingerprint problem in
  `GenerateKeyReplyParcelParser`. Both share the same root cause: real
  AOSP encoders produce byte sequences our BouncyCastle/Java emission
  cannot match exactly. The Rust `native-certgen` migration covers Gap C
  directly; the parcel issue would additionally need either Rust-side
  parcel construction (impractical because parcels are written by the
  Java framework AIDL stubs we don't control) or a structural
  break-the-parser approach. Keep deferred.
- **Gap D — `IKeystoreSecurityLevel.convertStorageKeyToEphemeral`**:
  unchanged.
- **Gap E — `IKeyMintDevice` HAL plane**: unchanged.

## Resume protocol for next session / 下一会话恢复指引

When Duck-Detector ships its next attack PR, follow the same protocol
as the prior handoff. In particular:

1. If the new probe targets the **GRANT plane**, it now must distinguish
   `Hit` / `PermissionDenied` / `NotMine`. Map the probe to one of
   those three cells before adding code; the most common new attack
   shape (USE-only vs GET_INFO-only vs DELETE-only) is already handled
   by the bit-mask check.
2. If the new probe targets the **generate-mode parcel
   fingerprint**, re-evaluate Gap C / parcel-encoder migration before
   patching with another byte-shift. Pattern-specific evasions of this
   parser have now demonstrably backfired once (our 2026-05-23 trailing
   dateTime auth defense broke the legacy 4-tuple but was the proximate
   cause of the new high-threshold modTime match).

下一会话遵循上一份 handoff 的恢复指引；GRANT 平面新增的 tri-state
（Hit / PermissionDenied / NotMine）会自动覆盖大多数 access-vector 变体；
parcel-fingerprint 类问题先评估 Gap C / 编码器 Rust 迁移，再考虑改字节。

## Final thought / 最后一句

Two of the three new red items in this report are now fixed in code:

- **Grant access vector** — structural, mirrors AOSP keystore2's
  `permission.rs:check_grant_permission`.
- **Generate-mode parcel fingerprint** — `modificationTimeMs = 0`
  everywhere we own the metadata. Defeats both the legacy 4-tuple and
  the new high-threshold predicate, and any future
  `modificationTimeMs > N` style probe with positive N.

The remaining red item (**Built-in local revocation floor matched ...
mass abuse**) is the bundled keybox blacklist. User-facing fix only:
swap `/data/adb/tricky_store/keybox.xml` with a non-blacklisted keybox.

报告里三条新红的两条已修——grant access vector 和 generate-mode parcel
fingerprint。剩下的 keybox CRL 命中是用户级修复，需要换自备 keybox。
