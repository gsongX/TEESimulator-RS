# TODO — Gap C: Rust 编码器字节级对齐 AOSP（Option 2 验证）

**状态**：暂缓（Deferred）
**触发时机**：当 Duck Detector 出 ASN.1 byte-level 比对类探针时立即启动
**预计工作量**：3–5 个工作日（仅验证 + 修差异；不含 BouncyCastle 路径迁移）
**作者范围**：自用 + 小范围分享。**不做** Option 3（PATCH 路径迁移到 Rust）——那个扔给上游。

---

## 为什么暂缓

1. **TEE 假死设备已经走 Rust 路径**。本机（OnePlus PJZ110，BL 解锁）在
   `DeviceAttestationService.checkTeeFunctionality()` 里返回 false，AUTO 模式翻成
   GENERATE，`doSoftwareKeyGen → generateAttestedKeyPairNative` 优先调 Rust，
   失败才 fallback BouncyCastle。日常用例下 attestation extension 字节由
   `native-certgen/src/attestation.rs` 生成。
2. **Rust 这条路的 DER 编码已经写得规范**：ENUMERATED 不是 INTEGER、BOOLEAN
   TRUE = 0xFF、字段按 tag 排序、explicit context-specific tag 的 base-128
   编码、SET OF INTEGER 按编码字节排序——这些都是和 AOSP 一致的硬性细节。
3. **Duck Detector 至今走的都是低工程量攻击**（grant 跨平面、parcel 字节启发式
   walker、缓存比对）。ASN.1 byte-level diff 工程量大，他们暂时没动。
4. **目标使用面窄**——自用 + 小范围。Option 3 全量迁移收益主要在 TEE 工作的
   设备上（PATCH 路径），不属于自用场景。

## 触发条件

凡是 Duck Detector 出现以下任一**新**探针，立刻启动这条 TODO：

- 探针读 attestation extension 的 raw DER bytes 做 SHA-256 / hex 比对
- 探针解析 KeyDescription SEQUENCE 后逐字段 byte-by-byte 与参考实现对比
- 探针报告里出现 `extensionFingerprint` / `asn1Bytes` / `derHash` 之类字段
- 探针 verdict 包含 `KEYDESC_ENCODER_DRIFT` / `ATTESTATION_BYTES_MISMATCH`
  这种描述

如果只是字段值层面的检查（OS_VERSION 不对、osPatchLevel 太老、
verifiedBootKey 是默认值），那是 Gap A/B/D 范畴，**不是** Gap C，不要走这条
TODO。

---

## 工作分解（按可独立交付的小步骤）

### Step 0：环境准备（半天）

- 拿一台未刷模块的真 Pixel（任何代有 KeyMint TA 的都行——Pixel 6 及以上）
- 装 keyattestation app 或类似工具，能抓 attestation extension 字节
- 一台装本模块的真机（现成的 OnePlus 即可），关掉 Duck Detector 的 keybox
  blacklist（用自备 keybox），让 Rust 路径全程走完
- 准备 Python/Rust 对 DER 做 byte-by-byte diff 的脚本

### Step 1：抓参考字节（1 天）

每组测试参数下，分别从「真 Pixel」和「装模块的设备」抓 attestation
extension 字节。最少要覆盖：

- EC P-256 + PURPOSE_SIGN + DIGEST_SHA256（最常见）
- EC P-256 + PURPOSE_SIGN + DIGEST_SHA384
- EC P-384 + PURPOSE_SIGN + DIGEST_SHA384
- RSA 2048 + PURPOSE_SIGN + PADDING_PKCS1
- RSA 2048 + PURPOSE_ENCRYPT + PADDING_OAEP
- 带 `setUserAuthenticationRequired(true)` 的版本（触发更多 tag）
- 带 `setKeyValidityForOriginationEnd` 的版本（活动期边界）
- attestVersion 200 / 300 / 400 三档（如果设备覆盖得到）

每组保存 raw DER 字节、解析后的 ASN.1 树。

### Step 2：跑 diff（半天）

写个 ASN.1 树状 diff 工具：

- 同 OID/同结构的 SEQUENCE 做递归比对
- 对每一处差异打 tag 出来：是字段集合差（Pixel 有但我们没有 / 反之）、字段值
  差、字段顺序差、INTEGER 字节编码差（非最小？多余前导 0xFF？）、ENUMERATED
  vs INTEGER 混用，等等
- 排除掉**预期差异**（boot key、boot hash、challenge、cert serial
  这些**应该**不一样，是设备特征）

输出一份「可疑差异列表」。

### Step 3：分类差异（1 天）

每条差异打三选一标签：

- **D1（Rust 编码器 bug）**：DER 写得不规范，应当修
- **D2（字段集合不一致）**：Rust 的 `build_software_enforced` /
  `build_tee_enforced` 字段划分和 AOSP `tag/info.rs` 的
  `KEYMINT_ENFORCED_CHARACTERISTICS` 表不一致
- **D3（设备相关，预期）**：忽略

最关键的是查 D2。AOSP 真值表位置：

```
system/keymint/common/src/tag/info.rs
  KEYMINT_ENFORCED_CHARACTERISTICS  // tee_enforced
  KEYSTORE_ENFORCED_CHARACTERISTICS // sw_enforced
```

把这两个表抄下来，一行一行核对 `attestation.rs` 里的 `(tag, fields)` 划分。

### Step 4：修 Rust（1–2 天）

根据 D1 / D2 分类，按差异条数决定改动范围。**如果 D2 出现得多，可以考虑把
两个 enforced characteristics 表直接抄到 Rust 里、按表生成代码**——这样以后
AOSP 版本变了，对一下表就行。

每改一条，跑 Step 1 的对比验证它消失。

### Step 5：回归测试（半天）

- 跑 Duck Detector 现有探针，确认 generate-mode parcel fingerprint /
  metadata shape / grant 等所有以前清过的红卡仍然清
- 确认 keyattestation app 解析 attestation extension 不报错
- 装机过 Play Integrity（如果你在意的话）

如果 5 全过，本 TODO 关闭。

---

## 不做的事（明确 scope）

- **不**迁移 `AttestationPatcher.patchCertificateChain` 这条 BouncyCastle
  路径到 Rust。那条只在 PATCH 模式（TEE 工作设备）触发，本机不走，且面向
  上游 fork 用户。这是 Option 3，扔给上游做。
- **不**写 Rust 的`AttestationApplicationId` 嵌套 SEQUENCE 编码器。当前 Kotlin
  那边已经把 AttestationApplicationId 编码成 byte[] 传过来，Rust 只把它套在
  OCTET STRING 里。除非 Step 3 发现 AttestationApplicationId 内部字节本身就
  有 D1/D2 差异（理论上可能，因为 BouncyCastle vs AOSP 的 SET OF
  AttestationPackageInfo 排序规则可能不同），否则不动。
- **不**改 `KeyMintAttestation` Kotlin 数据类——它只是 Rust 的输入参数容器，
  不参与编码。

## 触发后第一步

不要直接开干 Step 0。先做 5 分钟的判断：

1. 看 Duck Detector PR 描述，确认是不是 ASN.1 byte 比对探针
2. 跑现有 Duck Detector 检测一次，看是不是真的我们这边挂了
3. 如果是的，再看本 TODO 的 Step 0–5

如果 Duck Detector 出的是别的方向（grant / parcel / 缓存类），**不开**这条
TODO，按现有打补丁式响应即可。

---

## 关键文件位置

```
native-certgen/
├── Cargo.toml                 # Rust crate 配置
├── src/
│   ├── lib.rs                 # JNI 入口 generateAttestedKeyPair
│   ├── attestation.rs         # 我们要改的：build_attestation_extension
│   ├── certbuilder.rs         # 证书链构造（DER 编码细节也在这）
│   ├── keygen.rs              # EC/RSA 密钥对生成
│   └── keybox.rs              # keybox.xml 解析

app/src/main/java/org/matrix/TEESimulator/
├── attestation/
│   ├── AttestationBuilder.kt   # BouncyCastle 编码（本 TODO 不动）
│   ├── AttestationPatcher.kt   # PATCH 路径（Option 3 才动）
│   └── DeviceAttestationService.kt  # isTeeFunctional 探测
└── pki/
    ├── NativeCertGen.kt       # JNI 包装
    ├── CertGenConfig.kt       # 传给 Rust 的参数容器
    └── CertificateGenerator.kt # 同时调 Rust 和 BouncyCastle 的入口
```

AOSP 参考代码（每条 D2 都要回到这里核对）：

```
platform/system/keymint/common/src/
├── cert.rs              # build_subject_alt_name / 证书构造
├── tag/info.rs          # KEYMINT_ENFORCED_CHARACTERISTICS 真值表 ⭐
└── keyblob/sdd_mem.rs   # SDD 序列化（不太相关）
```
