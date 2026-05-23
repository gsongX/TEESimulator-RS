# Duck-Detector Grant-Domain Defense — Session Handoff (2026-05-23)

Branch: `fix/duck-detector-grant-domain-defense`
Status: 6 commits landed, Workflow build green, on-device verified clean against
Duck-Detector PRs #34 / #38 / #43. **Defense intentionally stopped here** — see
"Stop rationale" below before adding more.

分支：`fix/duck-detector-grant-domain-defense`
状态：6 个 commit 已落地，工作流编译通过，装机验证 Duck-Detector PR #34 / #38 / #43
下所有红卡均消除。**本轮防御主动止步于此** — 继续加固前请先读"停手理由"。

---

## Branch state / 分支状态

```text
e820c94 feat(intercept): hook IKeystoreMaintenance for software-key cache parity
b05b79e fix(intercept): emit CERTIFICATE_NOT_BEFORE/AFTER as keystore-enforced auths
cbc7f51 ci(build): grant explicit read permission to checkout
8d8e6a5 docs(plans): record duck-detector grant-domain defense
ca5e3a9 build(gradle): allow non-ASCII project paths
21b2e4a fix(intercept): unify GRANT plane with APP/KEY_ID for software keys
```

All authored by `Andrea-lyz <Andrea-lyz@users.noreply.github.com>`.
全部由 `Andrea-lyz <Andrea-lyz@users.noreply.github.com>` 签发。

---

## What was attacked / 被攻击的几个点

Duck-Detector PRs analyzed in this session:

本轮分析的 Duck-Detector PR：

- `eltavine/Duck-Detector-Refactoring#34` (`69cea7b7`) — count-independent
  generate-mode parcel fingerprint that walks the AIDL reply at
  12-byte-plus-payload strides and matches a 4-tuple
  `(lastSecLevel=256, lastTag=1, lastUnionTag=32, modTimeMs=0x100000001)`.
- `eltavine/Duck-Detector-Refactoring#38` (`b610f8e7`) — grant-domain full-chain
  split + importKey retained narrative + timing tightening.
- `eltavine/Duck-Detector-Refactoring#43` (`99a90742`) — three-stage grant probe
  (public KeyStoreManager → hidden Java reflection → private binder transact)
  plus updateSubcomponent stale persistence.

PR #34 利用 AIDL stable parcelable 的 length wrapper 跟探针 parser 之间的对齐错位，
用偏移读到的字节凑出 4-tuple 指纹；PR #38 / #43 引入 Domain.GRANT 跨平面比对、
importKey 后的链回放检测，以及 updateSubcomponent 后的 SHA-256 留存指纹。

---

## Defense contract now in place / 当前防御契约

**Invariant**: every keystore2-process interface that observes or mutates a
software-key alias sees one source of truth.

**核心不变性**：keystore2 进程内每一个观察或修改软件 key alias 的接口，
看到的都是同一份事实来源。

| keystore2 surface 接口面 | Coverage 覆盖 |
|---|---|
| `IKeystoreService.getKeyEntry(APP, alias)` | ✅ patched chain returned (existing) |
| `IKeystoreService.getKeyEntry(KEY_ID, nspace)` | ✅ resolves to same response |
| `IKeystoreService.getKeyEntry(GRANT, grantId)` | ✅ resolves to owner's response (`21b2e4a`) |
| `IKeystoreService.deleteKey` | ✅ existing, drops cache + grants (`21b2e4a` extension) |
| `IKeystoreService.updateSubcomponent` | ✅ updates leaf+chain in-place, evicts stale `patchedChains` (`21b2e4a`) |
| `IKeystoreService.grant` / `ungrant` | ✅ synthetic `softwareGrants` table (`21b2e4a`) |
| `IKeystoreService.listEntries` / `listEntriesBatched` / `getNumberOfEntries` | ✅ existing, software keys appear in counts |
| `IKeystoreSecurityLevel.generateKey` (post-transact) | ✅ patches chain, caches in `teeResponses` + `patchedChains` |
| `IKeystoreSecurityLevel.importKey` | ✅ existing, retains chain via `patchedChains` |
| `IKeystoreSecurityLevel.createOperation` | ✅ existing, forwards to `SoftwareOperation` for software keys |
| `IKeystoreMaintenance.deleteAllKeys` | ✅ `clearAllGeneratedKeys` (`e820c94`) |
| `IKeystoreMaintenance.clearNamespace(APP, uid)` | ✅ drops cache by uid (`e820c94`) |
| `IKeystoreMaintenance.onUserRemoved(userId)` | ✅ drops cache by uid range (`e820c94`) |
| `IKeystoreMaintenance.migrateKeyNamespace` | ✅ renames cache entry (`e820c94`) |

Authorization list shape changes that aligned with real AOSP HAL output:

为对齐真实 AOSP HAL 输出而调整的 authorization 列表形状：

- HAL-enforced auths reordered so `KEY_SIZE` lives at slot 2 (`c89f147`,
  pre-existing).
- Keystore-enforced auths use `SecurityLevel.KEYSTORE = 100` instead of
  `SOFTWARE = 0` (pre-existing).
- `CERTIFICATE_NOT_BEFORE` / `CERTIFICATE_NOT_AFTER` appended as trailing
  keystore-enforced `dateTime` auths (`b05b79e`) — both more accurate to AOSP
  KeyMint reference TA *and* shifts the parcel bytes the PR #34 parser reads
  off the magic positions.

---

## Stop rationale / 停手理由

**Decision**: do NOT add further defenses speculatively. Wait for Duck-Detector's
next concrete PR before acting.

**决定**：不再做预测性加固，等 Duck-Detector 下一个具体 PR 出现再行动。

Reasoning:

1. **Cat-and-mouse never terminates by writing more pre-emptive code.** Every
   detection vector we have evidence for is now covered. Anything beyond is a
   guess.
2. **Pre-emptive interceptors carry real cost.** Each one is a branch on a
   binder-hot path, a reflection cache, and a potential bug surface inside
   `system_server` adjacent code.
3. **My prediction accuracy was mixed this session.** I predicted `getKey-`
   `Characteristics` as a high-probability vector and on second look it does
   not exist on `IKeystoreSecurityLevel` at all — that prediction would have
   produced dead code.
4. **We have no on-device way to verify a speculative fix.** Without a probe
   binary that actually tries the attack we are guessing whether the fix lands
   on the right bytes / fields.

理由：
1. **写更多预防性代码不会终结猫鼠游戏。** 已经有证据的攻击向量都已覆盖；
   再往外都是猜测。
2. **预防性 interceptor 不是免费的。** 每一个都是 binder 热路径上的分支、
   一份 reflection 缓存、一处潜在 bug，而且改的是 system_server 邻近代码。
3. **本轮我的预测准确率不高。** 我把 `getKeyCharacteristics` 列为高概率攻击面，
   后来发现 `IKeystoreSecurityLevel` 上根本没有这个方法 — 按预测做就会留下死代码。
4. **没有真探针就没法验证假设性修复。** 没有探针二进制实际打这个点，我们只能猜
   修复有没有打到正确的字节/字段。

---

## Known gaps preserved for future sessions / 留给未来会话的已知缺口

These are theoretical attack surfaces that are NOT currently being exploited.
Document them so the next session does not have to re-derive them, but resist
fixing them without a concrete probe.

下面是**当前没有被利用**但理论上存在的攻击面。记下来是为了下一会话不必重新推导，
但**没有具体探针就别动**。

### Gap A — `IKeystoreSecurityLevel.deleteKey`

**What**: AOSP `IKeystoreSecurityLevel` (the per-security-level binder) has its
own `deleteKey(KeyDescriptor key)` method. Apps usually delete via the parent
`IKeystoreService.deleteKey`, which we already intercept. But a probe could
binder-transact directly against the security-level binder.

**Risk**: medium. Real keystore2 forwards security-level deleteKey through the
same internal database, so the only divergence is that our software-key cache
won't see this path.

**Fix when needed**: add `DELETE_KEY_TRANSACTION` to
`KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES` and dispatch to
`KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)` on pre-transact.

**内容**：AOSP `IKeystoreSecurityLevel`（每个安全级别的 binder）有自己的
`deleteKey(KeyDescriptor key)`。应用一般走父级 `IKeystoreService.deleteKey`
（我们已拦），但探针可以直接 binder transact 安全级别 binder。

**风险**：中。真实 keystore2 把安全级别 deleteKey 路由到同一个内部数据库，
差异只是我们的软件 key cache 不会被这条路径触发。

**真要修时**：在 `KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES` 里加上
`DELETE_KEY_TRANSACTION`，pre-transact 时分发到 `cleanupKeyData(keyId)`。

### Gap B — `softwareGrants` not persisted across reboot

**What**: Real keystore2 grants are stored in the SQLite `keyentries`
database and survive reboot. Our synthetic `softwareGrants` map is in-memory
only.

**Risk**: low-medium. A probe that issues a grant, force-stops keystore2,
verifies the grant still works via `getKeyEntry(GRANT, grantId)` would
detect us. Most probes don't do reboot-spanning state checks.

**Fix when needed**: extend `GeneratedKeyPersistence` to also serialize the
`softwareGrants` table; restore on `loadPersistedKeys`. Keep grantee UID
and ownerKeyId, regenerate grantId on restore.

**内容**：真实 keystore2 grant 存在 SQLite `keyentries` 表里跨重启持久化；
我们的合成 `softwareGrants` 只在内存。

**风险**：低-中。探针发起 grant、强杀 keystore2、再用
`getKeyEntry(GRANT, grantId)` 验证 grant 是否仍然有效就能识别。多数探针不做
跨重启的状态检查。

**真要修时**：扩展 `GeneratedKeyPersistence` 把 `softwareGrants` 也序列化；
`loadPersistedKeys` 时恢复，保留 granteeUid 和 ownerKeyId，重启后重发 grantId。

### Gap C — Attestation extension ASN.1 byte-level fingerprint

**What**: The attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) is
re-encoded by BouncyCastle on every patched leaf. AOSP KeyMint reference
TA emits the same extension via Rust `der` crate. The two encoders may
differ on:

- INTEGER minimal-byte encoding at boundary values
- SET-OF element ordering (DER requires sort by encoded byte sequence,
  not by tag number — we currently `sortedBy { it.tagNo }`)
- OPTIONAL NULL omission vs explicit `NULL`
- BIT STRING trailing pad-bit count

**Risk**: medium. A probe that captures a real-hardware attestation extension
once and SHA-256-prefixes the encoded bytes for comparison would see us
diverge. None of the public Duck-Detector PRs do this yet.

**Fix when needed**: route attestation extension construction through the
Rust `native-certgen` crate (which already exists for keypair generation)
so the encoder matches AOSP's. Cost is non-trivial — requires moving
`AttestationPatcher.createPatchedAttestationExtension` into Rust.

**内容**：attestation extension（OID `1.3.6.1.4.1.11129.2.1.17`）在每张
patched leaf 上由 BouncyCastle 重新编码。AOSP KeyMint reference TA 用 Rust
`der` crate 出同样 extension。两个编码器可能在以下点有差异：
- 边界值上 INTEGER 最小字节编码
- SET-OF 元素排序（DER 要求按编码字节序排，不是 tag 号；我们目前用
  `sortedBy { it.tagNo }`）
- OPTIONAL NULL 省略 vs 显式 `NULL`
- BIT STRING 末尾 pad-bit 计数

**风险**：中。探针抓一份真硬件 attestation extension 做 SHA-256 prefix 对比就
能识破我们。Duck-Detector 公开 PR 目前都没这么打。

**真要修时**：把 attestation extension 构造移到 Rust 的 `native-certgen`
crate（keypair 生成已经在那边），让编码器与 AOSP 一致。成本不小 — 要把
`AttestationPatcher.createPatchedAttestationExtension` 移到 Rust。

### Gap D — `IKeystoreSecurityLevel.convertStorageKeyToEphemeral`

**What**: API that derives an ephemeral key from a storage-bound key.
Software-generated attestation keys never go through this path because
they aren't storage keys.

**Risk**: very low. Cannot meaningfully fingerprint software keys via this
API.

**Fix when needed**: probably never. Document and ignore.

**内容**：从存储绑定 key 派生临时 key 的 API。我们生成的软件 attestation
key 永远不走这条路（不是 storage key）。

**风险**：极低。这条 API 实质上没法用来识别软件 key。

**真要修时**：大概率永远不需要。记录后忽略即可。

### Gap E — `IKeyMintDevice` HAL plane

**What**: The KeyMint HAL binder
(`android.hardware.security.keymint.IKeyMintDevice/default`) is one layer
below keystore2. SELinux normally allows only the `keystore` domain to
access it.

**Risk**: low for unrooted devices, higher on OEM builds with relaxed
SELinux. A probe with `system_server` reach could call `getKeyCharacteristics`
or attempt `addRngEntropy` and observe the HAL's lack of awareness about
our software keys.

**Fix when needed**: would require injecting into the HAL process itself
(separate from keystore2) and replicating the `generateKey` / `deleteKey` /
`getKeyCharacteristics` cache there. Significant effort. Do not start
without an actual probe.

**内容**：KeyMint HAL binder（`android.hardware.security.keymint.IKeyMint-`
`Device/default`）位于 keystore2 下一层。SELinux 默认只允许 `keystore` 域访问。

**风险**：未 root 设备低；OEM 放宽 SELinux 的设备较高。能触达 system_server
的探针可调 `getKeyCharacteristics` 或 `addRngEntropy`，观察 HAL 对软件 key 一无所知。

**真要修时**：要往 HAL 进程本身注入（不同于 keystore2）并在那边复制
`generateKey` / `deleteKey` / `getKeyCharacteristics` 缓存。工程量大。
**没有具体探针不要起步**。

---

## Resume protocol for next session / 下一会话恢复指引

When Duck-Detector ships its next attack PR:

Duck-Detector 出下一个攻击 PR 时：

1. **Read the patch** end-to-end to identify the new probe class. Pay special
   attention to (a) which transaction is exercised, (b) which fields the
   probe parses out of the response, (c) the matching predicate.

   先**读完整 patch**，识别新探针类。重点关注：(a) 调用了哪个 transaction，
   (b) 从响应中解析了哪些字段，(c) 匹配条件是什么。

2. **Map the probe to the Defense contract table above**. If it lives within
   one of the rows we already cover, the existing contract should have caught
   it — investigate why it didn't (could be a real bug; could be that our
   contract is too narrow). If it lives outside, it is a new attack surface;
   evaluate against the Stop rationale before adding code.

   把探针映射到上面的"防御契约"表。如果它属于我们已覆盖的行，按理我们的契约
   应该挡住 — 要查为什么没挡住（可能是 bug，也可能是契约定义太窄）。如果它
   在表外，就是新攻击面；用"停手理由"再评估一次再决定写不写代码。

3. **Cross-check with Gaps A–E above** before opening a new investigation.
   Some "new" probes will turn out to exercise a gap we already documented.

   开新调查前先核对上面 Gap A–E。有些"新"探针其实就是我们已记录的某个 gap 被触发。

4. **Test on device against the actual probe binary**, not against unit-test
   fixtures. Duck-Detector's parser builds reproducer fixtures that may
   diverge from what the device actually emits — we have already seen one
   such instance (PR #34's hex fixture vs real `System.currentTimeMillis()`
   timestamps). Always trust the device.

   **拿真探针二进制装机测**，不要对着单测 fixture 改。Duck-Detector parser 自带
   的 fixture 字节常和设备实际输出不一致 — 本轮已经踩过一次（PR #34 hex fixture
   vs 设备真实 `System.currentTimeMillis()` 时间戳）。**永远以设备为准**。

5. **Keep changes minimal and structural**. Pattern-specific evasions (rename
   a tag, shift a byte) age badly. Structural fixes (new interceptor row in
   the contract table, new cache invariant) age well. The GRANT-domain unify
   in `21b2e4a` is the model: it doesn't care what the probe does, it ensures
   the cross-API invariant holds.

   改动**保持最小且结构性**。模式针对性绕过（改 tag 名、移字节）会老化得很快；
   结构性修复（契约表里加一行、加一个 cache 不变性）能老化得很久。`21b2e4a`
   GRANT 域统一是范式：它不关心探针做什么，只保证跨 API 不变性成立。

---

## Files of interest / 关键文件位置

```
app/src/main/java/org/matrix/TEESimulator/interception/keystore/
├── Keystore2Interceptor.kt                  # IKeystoreService entry point
├── Keystore2MaintenanceInterceptor.kt       # IKeystoreMaintenance (e820c94 — new)
├── KeystoreInterceptor.kt                   # legacy Android Q/R path (untouched)
├── AbstractKeystoreInterceptor.kt           # service bootstrap + DeathRecipient
├── InterceptorUtils.kt                      # parcel reply helpers
├── ListEntriesHandler.kt                    # listEntries injection
└── shim/
    └── KeyMintSecurityLevelInterceptor.kt   # generateKey / importKey / createOp
                                              # + softwareGrants table (21b2e4a)
                                              # + CERTIFICATE_NOT_*  (b05b79e)
stub/src/main/java/android/security/maintenance/
└── IKeystoreMaintenance.java                # compileOnly stub (e820c94 — new)
```

---

## Verification artifacts / 验证 artifact

- Workflow: https://github.com/Andrea-lyz/TEESimulator-RS-Online/actions/workflows/build.yml
- Branch: https://github.com/Andrea-lyz/TEESimulator-RS-Online/tree/fix/duck-detector-grant-domain-defense
- On-device verification: confirmed by user on 2026-05-23. All Duck-Detector
  rows previously firing (`Grant isolated-domain`, `Grant self-domain`,
  `TEE Simulator generate-mode fingerprint`) now clean.
- 装机验证：用户于 2026-05-23 确认。之前红卡的三行
  （`Grant isolated-domain` / `Grant self-domain` /
  `TEE Simulator generate-mode fingerprint`）全部清零。

---

## Final thought / 最后一句

The defense is good enough. Don't fix what isn't broken yet. Watch for the
next concrete attack and respond to it specifically.

防御已经足够。还没坏的别去修。盯着下一次具体攻击，针对性回应。
