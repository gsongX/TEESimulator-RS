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
de693c0 fix(intercept): resolve Domain.GRANT readback before UID skip check
5d30165 docs(plans): clarify Gap C attack cost and response constraints
bcbd730 docs(plans): finalize duck-detector grant-domain defense handoff
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
| `IKeystoreService.getKeyEntry(GRANT, grantId)` | ✅ resolves to owner's response — upfront, **before** UID-skip check; resolver is grantee-bound so foreign callers fall through (`21b2e4a` + `de693c0` + 2026-05-26 cali-hash followup) |
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
TA emits the same extension via Rust `der` crate
(`system/keymint/common/src/cert.rs`). The two encoders are
**deterministically different** in ways that are **invariant across all real
hardware**: any AOSP KeyMint TA on any device uses the same Rust code path,
so an encoder-level difference detected on one Pixel is also true on every
other real device. Examples:

- AuthorizationList field emission order (driven by Rust struct field
  declaration order vs our `teeEnforcedMap.values.sortedBy { it.tagNo }`)
- Whether a field is emitted at OPTIONAL default values vs always omitted
- Empty SET-OF handled as omitted-OPTIONAL vs written-empty
- INTEGER minimal-byte encoding at boundary values
- BIT STRING trailing pad-bit count
- The `applicationId` / `attestationApplicationId` byte format

**Most damaging axis**: the *set* of fields emitted into `teeEnforced` vs
`softwareEnforced`. Real KeyMint TA splits authorizations by the
`KEYMINT_ENFORCED_CHARACTERISTICS` / `KEYSTORE_ENFORCED_CHARACTERISTICS`
tables in `tag/info.rs`. Our `toAuthorizations` follows a different (and
informally maintained) ruleset. Any single (algorithm, purpose,
securityLevel) tuple where the two rulesets disagree is a one-shot
fingerprint.

**Attack cost — single real device is enough**: this attack does NOT need a
device-database the way `os_patch_level` / `brand` / `device` content
fingerprints do. A probe author needs only one un-tampered Pixel:

1. Generate a key with chosen parameters → capture the attestation
   extension bytes.
2. Compare to the same key generated under TEESimulator-RS.
3. The first encoder-level diff that is independent of
   device-identifying fields becomes the fingerprint rule.

That said, the **engineering effort** to write such a probe is comparable
to PR #34 (generate-mode parcel fingerprint) — non-trivial ASN.1 decoding,
AOSP source-code cross-reference, Android-version coverage. Duck-Detector
has the skill but has so far preferred lower-effort cross-plane attacks.

**Risk**: medium. Single-device discoverable, but high engineering cost to
write the probe. Not currently exploited.

**Fix when needed**: route attestation extension construction through the
Rust `native-certgen` crate (which already exists for keypair generation)
so the encoder *and* the field-emission rules match AOSP byte-for-byte.
Cost is non-trivial — requires moving
`AttestationPatcher.createPatchedAttestationExtension` into Rust and
mirroring the AOSP `KEYMINT_ENFORCED_CHARACTERISTICS` table exactly.

**Note on response speed**: unlike GRANT/maintenance/parcel-fingerprint
fixes, this one is hard to iterate against on-device because the probe
itself does ASN.1 byte comparisons we cannot easily inspect from logcat.
If this lands, expect a slower fix cycle.

---

**内容**：attestation extension（OID `1.3.6.1.4.1.11129.2.1.17`）在每张
patched leaf 上由 BouncyCastle 重新编码。AOSP KeyMint reference TA 用 Rust
`der` crate（`system/keymint/common/src/cert.rs`）。**两个编码器在某些细节上
确定性不同，且这些不同不依赖具体设备** — 任意真机的 KeyMint TA 都跑同一份
Rust 代码，所以"在一台 Pixel 上发现的编码差异"在所有真机上都成立。差异点举例：

- AuthorizationList 字段出现顺序（真硬件由 Rust struct 字段声明序决定，
  我们由 `teeEnforcedMap.values.sortedBy { it.tagNo }` 决定）
- OPTIONAL default 值时是否省略
- 空 SET-OF 处理为"省略 OPTIONAL"还是"写空 SET"
- 边界值上 INTEGER 最小字节编码
- BIT STRING 末尾 pad-bit 计数
- `applicationId` / `attestationApplicationId` 的精确字节格式

**最致命**：`teeEnforced` / `softwareEnforced` 两个 list 中**字段集合本身**的
划分。真 KeyMint TA 严格按照 `tag/info.rs` 里的
`KEYMINT_ENFORCED_CHARACTERISTICS` / `KEYSTORE_ENFORCED_CHARACTERISTICS`
表决定每个 tag 进哪个 list；我们的 `toAuthorizations` 是非正式维护的另一套
规则。**任意一个 (algorithm, purpose, securityLevel) 组合下两套规则不一致**，
就成为一击必中的指纹。

**攻击成本——一台真机就够**：这条路**不需要**像 `os_patch_level` / `brand`
/ `device` 那种内容指纹一样维护机型数据库。探针作者只需要一台没刷模块的
Pixel：

1. 用指定参数生成一把 key → 抓 attestation extension 字节
2. 在装了 TEESimulator-RS 的设备上用同样参数重做一遍
3. 找到第一个**与设备识别字段无关**的编码差异 → 这就是指纹规则

但**写这种探针的工程量**和 PR #34（generate-mode parcel fingerprint）是同一级
别 — 复杂的 ASN.1 解析、AOSP 源码交叉对照、不同 Android 版本的覆盖。
Duck-Detector 团队有这个能力，但目前选了工程量更低的跨平面攻击路径。

**风险**：中。**单机可发现**，但探针工程量高。当前未被利用。

**真要修时**：把 attestation extension 构造移到 Rust 的 `native-certgen`
crate（keypair 生成已经在那边），让**编码器和字段划分规则**都按字节对齐
AOSP。成本不小 — 要把 `AttestationPatcher.createPatchedAttestationExtension`
移到 Rust，并精确镜像 AOSP `KEYMINT_ENFORCED_CHARACTERISTICS` 表。

**关于响应速度的提醒**：和 GRANT / maintenance / parcel-fingerprint 不同，这
条路的修复**很难靠装机迭代**——探针做的是 ASN.1 字节比较，logcat 里看不到。
真出 PR 的话，预期修复周期会比之前几轮长。

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

## Lessons from the 2026-05-25 incident / 2026-05-25 复盘

Duck-Detector PR `553e3fe` (2026-05-26) added two attack vectors. One we
fixed (`de693c0`), one we cannot fix in code:

PR `553e3fe`（2026-05-26）增加了两条新攻击点。一条已修（`de693c0`），一条无法在代码层修复：

### 1. ISOLATED_PRIVATE_READBACK_CRASH — fixed in de693c0

The probe binder-transacts `getKeyEntry(GRANT, grantId)` from an isolated
process whose UID is in 99000-99999 and matches the resulting keystore2
crash stack
(`No legacy keys for key descriptor / Error::Rc(r#KEY_NOT_FOUND) /
service.rs:157: while trying to load key info`).

Our 21b2e4a GRANT unification missed this case because
`Keystore2Interceptor.onPreTransact` runs `shouldSkipUid` before
dispatching to the GRANT resolver. Isolated UIDs have no package binding,
so `shouldSkipUid` always returns true for them and the call falls
through to real keystore2, which never registered our synthetic grantId.

**Lesson — single-source-of-truth invariants must apply to every UID that
touches the surface, not just the UIDs we have configured in
target.txt.** When a defense's invariant is "every reader sees the same
response", `shouldSkipUid`-style filters must come *after* the
invariant-resolving lookup, not before. The fix moves the GRANT resolver
ahead of the UID-skip check; if `softwareGrants` has the grantId, we
serve the owner's response no matter who is calling.

**经验**：当一个防御的不变性是"每个读者看到同样的响应"时，
`shouldSkipUid` 过滤器必须放在不变性查询**之后**，不能放在之前。否则 isolated
process / 系统服务 / 任何不在 target.txt 配置里的 UID 都会走真实路径，把同一表面
撕成两个不一致的视图。

### 1b. Ultrasonic Fingerprint cali hash regression (2026-05-26) — fixed follow-up to de693c0

The de693c0 fix moved the GRANT resolver ahead of `shouldSkipUid` so
isolated-app readbacks resolve from `softwareGrants`. That is structurally
correct for the duck-detector probe but introduced a cross-UID divergence:
**every** caller — including vendor TAs and the engineering-mode probe —
now hits the resolver, and the resolver only checked `softwareGrants[grantId]`,
not the recorded grantee UID.

Combined with `softwareGrantIdGen` seeded at `1L`, our synthetic grantIds lived
in the dense low-bit range where real hardware/vendor grant IDs are also
likely to land. When the fingerprint engineering-mode probe called
`getKeyEntry(Domain.GRANT, realGrantId)` for a vendor-issued grant whose ID
happened to collide with one of ours, we served the owner's cached
`KeyEntryResponse` instead of forwarding to real keystore2. Symptom on device:
工程模式 → 器件校准状态 → `[4]Ultrasonic.Fingerprint` showed
`[4001] Ultrasonic Fingerprint cali hash get failed` (red ×). Disabling
TEESimulator-RS restored the calibration readback.

**Fix (two structural pieces, no pattern-specific evasion)**:

1. `KeyMintSecurityLevelInterceptor.resolveGrantedResponse(grantId, callingUid)`
   now takes the caller UID and only resolves when the recorded
   `grant.granteeUid == callingUid`. Foreign callers (any UID we never issued
   a grant to) fall through to real keystore2 unchanged. Both call sites in
   `Keystore2Interceptor` (the upfront resolver and the post-skip fallback)
   were updated.
2. `softwareGrantIdGen` is now seeded with `SecureRandom` in the upper half
   of the positive 63-bit range
   (`(rand & 0x3fff_ffff_ffff_ffffL) | 0x4000_0000_0000_0000L`). The
   grantee-UID guard is the authoritative defense; this seeding is a
   probabilistic backup so the next regression of this shape gets a ~1/2^62
   collision floor instead of dense overlap.

**Lesson — single-source-of-truth invariants are bidirectional.** The 21b2e4a
unification said "every reader of the GRANT plane sees the same owner
response". The de693c0 fix made that hold for every UID. But the invariant
implicitly assumes "the reader is one of our grantees" — without that bound,
serving the owner response to a *foreign* caller breaks an even more important
invariant: **we never modify replies for callers we don't own**. Yesterday's
fix removed the wrong filter (`shouldSkipUid`); the right filter was always
"is the caller the recorded grantee", which is a property of the grant entry
itself, not of `target.txt`.

**经验**：单一真值源的不变性是**双向**的。21b2e4a 让"GRANT 平面的每个读者看到
相同的 owner 响应"，de693c0 让该不变性对每个 UID 都成立。但这个不变性隐含
"读者是我们的 grantee"——少了这条约束，把 owner 响应丢给一个陌生调用者就破坏
了一条更重要的不变性：**永不修改我们不拥有的调用者的响应**。昨天的修复去掉
了错误的过滤器（`shouldSkipUid`），正确的过滤器一直是"调用者是否就是登记的
grantee"，这是 grant 表项自带的属性，不是 `target.txt` 的属性。

The C++-side filter (`filtered_codes` in `binder_interceptor.cpp:248-254`)
only narrows by transaction code, not UID — so any defense that needs UID
scoping must add it explicitly in the Kotlin handler. There is no second
chance to add it later.

C++ 侧的 `filtered_codes` 只按 transaction code 过滤，不按 UID — 任何需要按
UID 限定的防御必须在 Kotlin handler 里显式加上，没有后置防线。

### 2. Hardcoded keybox serial revocation — not fixable in code

PR 553e3fe also added the EC leaf serial `8616ef30679ed43cc2b43e3c97a2319e`
of the project's bundled `keybox.xml` (`@Xiaomi_Lei_Jun` keybox) to
`tee_attestation_status.json` as a `KEY_COMPROMISE` entry. PR also wired
`mergeOnlineEntries` so this revocation cannot be downgraded by the
online feed — the local hardcoded list is the new revocation floor. So
both online and offline scans now match this serial as revoked
regardless of network state.

This is reverse-engineering then static blacklisting, not a technical
fingerprint we can defeat in the interceptor. Any keybox that gets
publicly distributed will eventually land on this list. Mitigation
options live outside of code:

PR 同时把项目自带的 `@Xiaomi_Lei_Jun` keybox EC leaf serial
`8616ef30679ed43cc2b43e3c97a2319e` 加进 `tee_attestation_status.json` 标为
`KEY_COMPROMISE`，并通过 `mergeOnlineEntries` 让在线源无法降级它。**联网/离线
扫描都会匹配这条 serial 命中红卡。**这是**反向工程后静态黑名单**，不是技术指纹，
不能在 interceptor 里绕。任何被公开流通的 keybox 早晚都会进这张表。能做的事情
只在代码外：

- Keep `customize.sh`'s idempotent install logic (already in place,
  `module/customize.sh:85-89`) so a user-supplied keybox at
  `/data/adb/tricky_store/keybox.xml` is never overwritten on module
  upgrade. 保持 `customize.sh` 的幂等安装逻辑，让用户自带 keybox 不被升级覆盖。
- Document in README that the bundled keybox is for demonstration and
  **will trigger Duck-Detector / PI revocation matches**; users who want
  clean attestation must supply their own. 在 README 写明自带 keybox 仅供演示，
  会被列黑；用户需自备未泄露的 keybox。
- Consider a startup self-check that hashes the leaf serial of the
  active keybox against a small embedded "known-blacklisted" list and
  emits a warning into logcat. Implementation deferred — would require
  shipping (and maintaining) our own copy of Duck-Detector's blacklist,
  which is fragile. 可选：启动时自检 active keybox leaf serial，命中已知黑名单
  时只输出 warning。延后——需要我们自己镜像并维护一份 Duck-Detector 黑名单，
  脆弱。

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
