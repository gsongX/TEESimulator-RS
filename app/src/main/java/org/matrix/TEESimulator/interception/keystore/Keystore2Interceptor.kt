package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.Build
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import java.security.SecureRandom
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.shim.GeneratedKeyPersistence
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

/**
 * Interceptor for the `IKeystoreService` on Android S (API 31) and newer.
 *
 * This version of Keystore delegates most cryptographic operations to `IKeystoreSecurityLevel`
 * sub-services (for TEE, StrongBox, etc.). This interceptor's main role is to set up interceptors
 * for those sub-services and to patch certificate chains on their way out.
 */
@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : AbstractKeystoreInterceptor() {
    private val stubBinderClass = IKeystoreService.Stub::class.java

    // Transaction codes for the IKeystoreService interface methods we are interested in.
    private val GET_KEY_ENTRY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getKeyEntry")
    private val DELETE_KEY_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "deleteKey")
    private val UPDATE_SUBCOMPONENT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "updateSubcomponent")
    private val LIST_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "listEntries")
    private val LIST_ENTRIES_BATCHED_TRANSACTION =
        if (Build.VERSION.SDK_INT >= 34)
            InterceptorUtils.getTransactCode(stubBinderClass, "listEntriesBatched")
        else null
    private val GET_NUMBER_OF_ENTRIES_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "getNumberOfEntries")
    // grant/ungrant exist on every Android 12+ IKeystoreService binder. They were
    // not previously intercepted because regular AOSP apps do not call them, but
    // detection probes do — exercising Domain.GRANT after generateKey/getKeyEntry
    // already returned our patched chain. Without a same-source response from the
    // GRANT plane, real keystore2 sees the alias as nonexistent and replies with
    // KEY_NOT_FOUND, which is a structural cross-plane divergence regardless of
    // any specific probe wording. We resolve the GRANT path the same way we
    // resolve KEY_ID — by serving the same KeyEntryResponse — so APP / KEY_ID /
    // GRANT all share one source of truth for software-generated keys.
    private val GRANT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "grant")
    private val UNGRANT_TRANSACTION =
        InterceptorUtils.getTransactCode(stubBinderClass, "ungrant")

    private val transactionNames: Map<Int, String> by lazy {
        stubBinderClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private const val RESPONSE_KEY_NOT_FOUND = 7
    private val deletedSoftwareKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
    private val userUpdatedKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()

    fun forgetDeletedKey(keyId: KeyIdentifier) {
        if (deletedSoftwareKeys.remove(keyId)) {
            SystemLogger.debug("Cleared deletion marker for ${keyId.alias}")
        }
    }

    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libTEESimulator.so entry"

    override val interceptedCodes: IntArray by lazy {
        listOfNotNull(
                GET_KEY_ENTRY_TRANSACTION,
                DELETE_KEY_TRANSACTION,
                UPDATE_SUBCOMPONENT_TRANSACTION,
                LIST_ENTRIES_TRANSACTION,
                LIST_ENTRIES_BATCHED_TRANSACTION,
                GET_NUMBER_OF_ENTRIES_TRANSACTION,
                GRANT_TRANSACTION.takeIf { it != -1 },
                UNGRANT_TRANSACTION.takeIf { it != -1 },
            )
            .toIntArray()
    }

    /**
     * This method is called once the main service is hooked. It proceeds to find and hook the
     * security level sub-services (e.g., TEE, StrongBox).
     */
    override fun onInterceptorReady(service: IBinder, backdoor: IBinder) {
        val keystoreInterface = IKeystoreService.Stub.asInterface(service)
        setupSecurityLevelInterceptors(keystoreInterface, backdoor)
        setupMaintenanceInterceptor(backdoor)
    }

    /**
     * Hook `IKeystoreMaintenance` so software-key cache stays consistent when callers use
     * `clearNamespace` / `deleteAllKeys` / `onUserRemoved` / `migrateKeyNamespace`. The maintenance
     * service runs in the same `keystore2` process, so the same backdoor binder is reusable.
     */
    private fun setupMaintenanceInterceptor(backdoor: IBinder) {
        runCatching {
            val maintenance = android.os.ServiceManager.getService(
                "android.security.maintenance"
            ) ?: return@runCatching
            val codes = Keystore2MaintenanceInterceptor.INTERCEPTED_CODES
            if (codes.isEmpty()) {
                SystemLogger.warning(
                    "IKeystoreMaintenance has no resolvable transaction codes on this build; skip."
                )
                return@runCatching
            }
            register(backdoor, maintenance, Keystore2MaintenanceInterceptor, codes)
            SystemLogger.info("Registered IKeystoreMaintenance interceptor (${codes.size} codes).")
        }.onFailure {
            // Maintenance interception is supplementary, not load-bearing — never crash the
            // main daemon when this fails. Probes may then observe a maintenance-vs-getKeyEntry
            // divergence on broken devices, but that is preferable to total interceptor death.
            SystemLogger.error("Failed to intercept IKeystoreMaintenance.", it)
        }
    }

    private fun setupSecurityLevelInterceptors(service: IKeystoreService, backdoor: IBinder) {
        // Attempt to get and intercept the TEE security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)?.let { tee ->
                    SystemLogger.info("Found TEE SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
                    register(
                        backdoor,
                        tee.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept TEE SecurityLevel.", it) }

        // Attempt to get and intercept the StrongBox security level service.
        runCatching {
                service.getSecurityLevel(SecurityLevel.STRONGBOX)?.let { strongbox ->
                    SystemLogger.info("Found StrongBox SecurityLevel. Registering interceptor...")
                    val interceptor =
                        KeyMintSecurityLevelInterceptor(strongbox, SecurityLevel.STRONGBOX)
                    register(
                        backdoor,
                        strongbox.asBinder(),
                        interceptor,
                        KeyMintSecurityLevelInterceptor.INTERCEPTED_CODES,
                    )
                    interceptor.loadPersistedKeys()
                }
            }
            .onFailure { SystemLogger.error("Failed to intercept StrongBox SecurityLevel.", it) }
    }

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return if (ConfigurationManager.shouldSkipUid(callingUid))
                TransactionResult.ContinueAndSkipPost
            else TransactionResult.Continue
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)

            val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
            val isGMS = packages.contains("com.google.android.gms")

            if (isGMS || ConfigurationManager.shouldSkipUid(callingUid)) {
                return TransactionResult.ContinueAndSkipPost
            }

            return runCatching {
                    val isBatchMode = code == LIST_ENTRIES_BATCHED_TRANSACTION
                    if (ListEntriesHandler.cacheParameters(txId, data, isBatchMode)) {
                        TransactionResult.Continue
                    } else {
                        TransactionResult.ContinueAndSkipPost
                    }
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to parse parameters for ${transactionNames[code]!!}",
                        it,
                    )
                    TransactionResult.ContinueAndSkipPost
                }
        } else if (
            code == GET_KEY_ENTRY_TRANSACTION ||
                code == DELETE_KEY_TRANSACTION ||
                code == UPDATE_SUBCOMPONENT_TRANSACTION
        ) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

            // Domain.GRANT readbacks must be honored regardless of UID skip:
            // grantee processes (especially isolated_app UID 99000-99999) have no
            // package binding, so shouldSkipUid is always true for them. If we early
            // return here, the call falls through to real keystore2, which has no
            // record of our synthetic grantId and replies with KEY_NOT_FOUND. That
            // is exactly the ISOLATED_PRIVATE_READBACK_CRASH signature Duck-Detector
            // PR 553e3fe added on 2026-05-26 to flag isolated grant-domain probes
            // as a WARN. Resolve the GRANT plane up front before any skip check so
            // every caller sees the owner's same KeyEntryResponse.
            if (code == GET_KEY_ENTRY_TRANSACTION) {
                val rewindMark = data.dataPosition()
                val grantHit = runCatching {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    if (descriptor != null &&
                        descriptor.alias == null &&
                        descriptor.domain == Domain.GRANT) {
                        KeyMintSecurityLevelInterceptor
                            .resolveGrantedResponse(descriptor.nspace)
                    } else null
                }.getOrNull()
                if (grantHit != null) {
                    SystemLogger.info(
                        "[TX_ID: $txId] Found generated response via GRANT grantId=" +
                            "(uid=$callingUid pre-skip)"
                    )
                    return InterceptorUtils.createTypedObjectReply(grantHit)
                }
                data.setDataPosition(rewindMark)
            }

            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost

            if (code == UPDATE_SUBCOMPONENT_TRANSACTION)
                return handleUpdateSubcomponent(callingUid, data)

            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost

            if (code == DELETE_KEY_TRANSACTION) {
                val keyId =
                    if (descriptor.alias != null) {
                        KeyIdentifier(callingUid, descriptor.alias)
                    } else if (descriptor.domain == Domain.KEY_ID) {
                        KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                            callingUid, descriptor.nspace
                        )?.let { info ->
                            KeyMintSecurityLevelInterceptor.generatedKeys.entries
                                .find { it.value.nspace == info.nspace && it.key.uid == callingUid }
                                ?.key
                        }
                    } else null

                if (keyId != null) {
                    val isSoftwareKey =
                        KeyMintSecurityLevelInterceptor.generatedKeys.containsKey(keyId)
                    KeyMintSecurityLevelInterceptor.cleanupKeyData(keyId)
                    if (isSoftwareKey) {
                        deletedSoftwareKeys.add(keyId)
                        SystemLogger.info(
                            "[TX_ID: $txId] Deleted cached keypair ${keyId.alias}, replying with empty response."
                        )
                        return InterceptorUtils.createSuccessReply(writeResultCode = false)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }

            if (descriptor.alias == null) {
                if (descriptor.domain == Domain.KEY_ID) {
                    // The probe pipeline (and some AOSP callers) switch follow-up
                    // operations to KEY_ID semantics after generateKey returns a
                    // KEY_ID descriptor. Without this branch, our software keys
                    // are invisible to KEY_ID-based getKeyEntry calls and the
                    // request falls through to the real keystore2 daemon, which
                    // legitimately responds with KEY_NOT_FOUND. Duck Detector's
                    // TimingSideChannelProbe captures that exception during its
                    // warmup phase and surfaces it as
                    // "Captured private binder exception during timing skip".
                    // Resolving by KEY_ID and returning the cached response keeps
                    // the call on the happy path, eliminating the warmup signal.
                    val info = KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid, descriptor.nspace
                    )
                    if (info?.response != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found generated response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        return InterceptorUtils.createTypedObjectReply(info.response)
                    }
                    val teeResp = KeyMintSecurityLevelInterceptor.findTeeResponseByKeyId(
                        callingUid, descriptor.nspace
                    )
                    if (teeResp != null) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Found TEE response via KEY_ID nspace=${descriptor.nspace}"
                        )
                        return InterceptorUtils.createTypedObjectReply(teeResp)
                    }
                } else if (descriptor.domain == Domain.GRANT) {
                    // Defense-in-depth: the upfront GRANT resolver right after the
                    // GET_KEY_ENTRY_TRANSACTION dispatch already handles this case
                    // for every UID (including isolated_app). We keep this branch
                    // as a backup in case the upfront parcel rewind ever fails on
                    // an exotic AOSP fork where data.setDataPosition is not
                    // idempotent. Cheap and harmless to leave here.
                    KeyMintSecurityLevelInterceptor.resolveGrantedResponse(descriptor.nspace)?.let { resp ->
                        SystemLogger.info(
                            "[TX_ID: $txId] Found generated response via GRANT grantId=${descriptor.nspace} (post-skip fallback)"
                        )
                        return InterceptorUtils.createTypedObjectReply(resp)
                    }
                }
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, descriptor.alias)

            val response = KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(keyId)
            if (response == null) {
                if (deletedSoftwareKeys.remove(keyId)) {
                    SystemLogger.info("[TX_ID: $txId] Returning KEY_NOT_FOUND for deleted key ${descriptor.alias}")
                    return InterceptorUtils.createErrorReply(RESPONSE_KEY_NOT_FOUND)
                }
                return TransactionResult.Continue
            }

            if (KeyMintSecurityLevelInterceptor.isAttestationKey(keyId))
                SystemLogger.info("${descriptor.alias} was an attestation key")

            SystemLogger.info("[TX_ID: $txId] Found generated response for ${descriptor.alias}:")
            response.metadata?.authorizations?.forEach {
                KeyMintParameterLogger.logParameter(it.keyParameter)
            }
            return InterceptorUtils.createTypedObjectReply(response)
        } else if (code == GRANT_TRANSACTION || code == UNGRANT_TRANSACTION) {
            logTransaction(txId, transactionNames[code] ?: "code=$code", callingUid, callingPid)
            if (ConfigurationManager.shouldSkipUid(callingUid))
                return TransactionResult.ContinueAndSkipPost
            return if (code == GRANT_TRANSACTION) handleGrant(txId, callingUid, data)
            else handleUngrant(txId, callingUid, data)
        } else {
            logTransaction(
                txId,
                transactionNames[code] ?: "unknown code=$code",
                callingUid,
                callingPid,
                true,
            )
        }

        // Let most calls go through to the real service.
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        if (target != keystoreService || reply == null) return TransactionResult.SkipTransaction
        if (InterceptorUtils.hasException(reply)) {
            val normalized = InterceptorUtils.normalizeServiceSpecificReply(reply)
            return if (normalized != null) TransactionResult.OverrideReply(normalized)
            else TransactionResult.SkipTransaction
        }

        if (code == GET_NUMBER_OF_ENTRIES_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            return runCatching {
                    val hardwareCount = reply.readInt()
                    val softwareCount =
                        KeyMintSecurityLevelInterceptor.generatedKeys.keys.count {
                            it.uid == callingUid
                        }
                    val totalCount = hardwareCount + softwareCount
                    val parcel = Parcel.obtain().apply {
                        writeNoException()
                        writeInt(totalCount)
                    }
                    TransactionResult.OverrideReply(parcel)
                }
                .getOrElse {
                    SystemLogger.error("[TX_ID: $txId] Failed to modify getNumberOfEntries.", it)
                    TransactionResult.SkipTransaction
                }
        } else if (code == LIST_ENTRIES_TRANSACTION || code == LIST_ENTRIES_BATCHED_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            return runCatching {
                    val updatedKeyDescriptors =
                        ListEntriesHandler.injectGeneratedKeys(txId, callingUid, reply)
                    InterceptorUtils.createTypedArrayReply(updatedKeyDescriptors)
                }
                .getOrElse {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to update the result of ${transactionNames[code]!!}.",
                        it,
                    )
                    TransactionResult.SkipTransaction
                }
        } else if (code == GET_KEY_ENTRY_TRANSACTION) {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction

            logTransaction(
                txId,
                "post-${transactionNames[code]!!} ${keyDescriptor.alias}",
                callingUid,
                callingPid,
            )

            if (!ConfigurationManager.shouldPatch(callingUid))
                return TransactionResult.SkipTransaction

            runCatching {
                    val response = reply.readTypedObject(KeyEntryResponse.CREATOR)!!
                    val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)

                    if (userUpdatedKeys.remove(keyId)) {
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: userUpdated=true, skipping patch" }
                        SystemLogger.debug("[TX_ID: $txId] Skipping cert patch for user-updated key $keyId.")
                        return TransactionResult.SkipTransaction
                    }

                    val authorizations = response.metadata.authorizations
                    val parsedParameters =
                        KeyMintAttestation(
                            authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()
                        )

                    SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: isImport=${parsedParameters.isImportKey()} origin=${parsedParameters.origin} inImportedKeys=${KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)} hasPatchedChain=${KeyMintSecurityLevelInterceptor.getPatchedChain(keyId) != null} isAttestKey=${parsedParameters.isAttestKey()}" }

                    if (parsedParameters.isImportKey()) {
                        val retainedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)
                        if (retainedChain == null) {
                            SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: imported, no retained chain, skip" }
                            SystemLogger.info("[TX_ID: $txId] Skip patching for imported key (no prior attestation).")
                            return TransactionResult.SkipTransaction
                        }
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: imported, SERVING RETAINED CHAIN (detection vector!)" }
                        SystemLogger.info("[TX_ID: $txId] Imported key overwrote attested alias, serving retained chain for $keyId")
                        CertificateHelper.updateCertificateChain(response.metadata, retainedChain).getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )
                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    if (KeyMintSecurityLevelInterceptor.importedKeys.contains(keyId)) {
                        SystemLogger.trace { "[TRACE-$txId] getKeyEntry $keyId: in importedKeys set, skip" }
                        SystemLogger.debug("[TX_ID: $txId] Skipping attest-key override for imported key $keyId")
                        return TransactionResult.SkipTransaction
                    }

                    if (parsedParameters.isAttestKey()) {
                        SystemLogger.warning(
                            "[TX_ID: $txId] Found hardware attest key ${keyId.alias} in the reply."
                        )
                        val keyData =
                            CertificateGenerator.generateAttestedKeyPair(
                                callingUid,
                                keyId.alias,
                                null,
                                parsedParameters,
                                response.metadata.keySecurityLevel,
                            ) ?: throw Exception("Failed to create overriding attest key pair.")

                        CertificateHelper.updateCertificateChain(
                                response.metadata,
                                keyData.second.toTypedArray(),
                            )
                            .getOrThrow()
                        response.metadata.authorizations =
                            InterceptorUtils.patchAuthorizations(
                                response.metadata.authorizations,
                                callingUid,
                            )

                        val newNspace = SecureRandom().nextLong()
                        response.metadata.key?.let { it.nspace = newNspace }
                        KeyMintSecurityLevelInterceptor.generatedKeys[keyId] =
                            KeyMintSecurityLevelInterceptor.GeneratedKeyInfo(
                                keyData.first,
                                null,
                                newNspace,
                                response,
                                parsedParameters,
                            )
                        KeyMintSecurityLevelInterceptor.attestationKeys.add(keyId)

                        // Snapshot metadata bytes for the same reason as the
                        // primary doSoftwareKeyGen path — loss-less restore
                        // after reboot.
                        val metadataBytesForPersist = response.metadata?.let { md ->
                            runCatching {
                                val parcel = android.os.Parcel.obtain()
                                try {
                                    md.writeToParcel(parcel, 0)
                                    parcel.marshall()
                                } finally {
                                    parcel.recycle()
                                }
                            }.getOrNull()
                        }
                        GeneratedKeyPersistence.save(
                            keyId = keyId,
                            keyPair = keyData.first,
                            secretKey = null,
                            nspace = newNspace,
                            securityLevel = response.metadata.keySecurityLevel,
                            certChain = keyData.second,
                            algorithm = parsedParameters.algorithm,
                            keySize = parsedParameters.keySize,
                            ecCurve = parsedParameters.ecCurve ?: 0,
                            purposes = parsedParameters.purpose,
                            digests = parsedParameters.digest,
                            isAttestationKey = true,
                            metadataBytes = metadataBytesForPersist,
                        )

                        return InterceptorUtils.createTypedObjectReply(response)
                    }

                    val originalChain = CertificateHelper.getCertificateChain(response)

                    if (originalChain == null || originalChain.size < 2) {
                        SystemLogger.info(
                            "[TX_ID: $txId] Skip patching short certificate chain of length ${originalChain?.size}."
                        )
                        return TransactionResult.SkipTransaction
                    }

                    val cachedChain = KeyMintSecurityLevelInterceptor.getPatchedChain(keyId)

                    val finalChain: Array<Certificate>
                    if (cachedChain != null) {
                        SystemLogger.debug(
                            "[TX_ID: $txId] Using cached patched certificate chain for $keyId."
                        )
                        finalChain = cachedChain
                    } else {
                        SystemLogger.info(
                            "[TX_ID: $txId] No cached chain for $keyId. Performing live patch as a fallback."
                        )
                        finalChain =
                            AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                        KeyMintSecurityLevelInterceptor.patchedChains[keyId] = finalChain
                    }

                    CertificateHelper.updateCertificateChain(response.metadata, finalChain)
                        .getOrThrow()
                    response.metadata.authorizations =
                        InterceptorUtils.patchAuthorizations(
                            response.metadata.authorizations,
                            callingUid,
                        )

                    return InterceptorUtils.createTypedObjectReply(response)
                }
                .onFailure {
                    SystemLogger.error(
                        "[TX_ID: $txId] Failed to modify hardware KeyEntryResponse.",
                        it,
                    )
                    return TransactionResult.SkipTransaction
                }
        }
        return TransactionResult.SkipTransaction
    }

    private fun handleUpdateSubcomponent(callingUid: Int, data: Parcel): TransactionResult {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            ?: return TransactionResult.ContinueAndSkipPost

        val generatedKeyInfo =
            when (descriptor.domain) {
                Domain.KEY_ID ->
                    KeyMintSecurityLevelInterceptor.findGeneratedKeyByKeyId(
                        callingUid, descriptor.nspace
                    )
                Domain.APP ->
                    descriptor.alias?.let {
                        KeyMintSecurityLevelInterceptor.generatedKeys[KeyIdentifier(callingUid, it)]
                    }
                else -> null
            }

        if (generatedKeyInfo == null) {
            descriptor.alias?.let {
                val kid = KeyIdentifier(callingUid, it)
                userUpdatedKeys.add(kid)
                SystemLogger.trace { "[TRACE] updateSubcomponent $kid: not generated key, added to userUpdatedKeys" }
            }
            return TransactionResult.ContinueAndSkipPost
        }

        SystemLogger.info("Updating sub-component with key[${generatedKeyInfo.nspace}]")
        val metadata = generatedKeyInfo.response.metadata
        val publicCert = data.createByteArray()
        val certificateChain = data.createByteArray()

        metadata.certificate = publicCert
        metadata.certificateChain = certificateChain

        // Defensive: evict the prior patched chain so any subsequent KEY_ID /
        // GRANT readback can never replay a SHA-256 fingerprint from before
        // the update. Without this, KeyMintSecurityLevelInterceptor.patchedChains
        // still holds the pre-update chain, which a probe could attribute to
        // stale TEE response persistence.
        val ownerKeyId = descriptor.alias?.let { KeyIdentifier(callingUid, it) }
            ?: KeyMintSecurityLevelInterceptor.generatedKeys.entries.firstOrNull {
                it.key.uid == callingUid && it.value.nspace == generatedKeyInfo.nspace
            }?.key
        ownerKeyId?.let { KeyMintSecurityLevelInterceptor.invalidatePatchedChainFor(it) }

        GeneratedKeyPersistence.rePersistIfNeeded(callingUid, generatedKeyInfo)

        SystemLogger.verbose(
            "Key updated with sizes: [publicCert, certificateChain] = [${publicCert?.size}, ${certificateChain?.size}]"
        )

        return InterceptorUtils.createSuccessReply(writeResultCode = false)
    }

    /**
     * Handles `IKeystoreService.grant(KeyDescriptor, granteeUid)`.
     *
     * For software-generated owner aliases we issue a synthetic grantId and
     * store the mapping `grantId -> ownerKeyId`. Subsequent
     * `getKeyEntry(Domain.GRANT, grantId)` calls then resolve to the same
     * KeyEntryResponse the owner sees, keeping the GRANT plane structurally
     * consistent with the APP / KEY_ID planes for software keys.
     *
     * For non-software keys we forward to real keystore2 unchanged, since the
     * AOSP grant path can resolve them legitimately.
     */
    private fun handleGrant(txId: Long, callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return@runCatching TransactionResult.ContinueAndSkipPost
            val granteeUid = data.readInt()
            // accessVector is the third arg; we do not need it because software
            // keys do not enforce per-grant permission masks here.

            val ownerKeyId = resolveOwnerKeyId(callingUid, descriptor) ?: run {
                SystemLogger.debug(
                    "[TX_ID: $txId] grant for non-software key (domain=${descriptor.domain} alias=${descriptor.alias} nspace=${descriptor.nspace}); forwarding."
                )
                return@runCatching TransactionResult.ContinueAndSkipPost
            }

            val grantId = KeyMintSecurityLevelInterceptor.issueSoftwareGrant(ownerKeyId, granteeUid)
            SystemLogger.info(
                "[TX_ID: $txId] Issued software grant for $ownerKeyId -> uid=$granteeUid grantId=$grantId"
            )

            val granted = KeyDescriptor().apply {
                domain = Domain.GRANT
                nspace = grantId
                alias = null
                blob = null
            }
            InterceptorUtils.createTypedObjectReply(granted)
        }.getOrElse {
            SystemLogger.error("[TX_ID: $txId] Failed to handle grant", it)
            // On any failure, forward to real keystore2 so we never become a
            // detection vector ourselves by inventing inconsistent replies.
            TransactionResult.ContinueAndSkipPost
        }
    }

    /**
     * Handles `IKeystoreService.ungrant(KeyDescriptor, granteeUid)`.
     *
     * If the descriptor matches a software-generated owner alias we synthesize
     * a successful reply and drop the synthetic grant entry. Otherwise we
     * forward to real keystore2.
     */
    private fun handleUngrant(txId: Long, callingUid: Int, data: Parcel): TransactionResult {
        return runCatching {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val descriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return@runCatching TransactionResult.ContinueAndSkipPost
            val granteeUid = data.readInt()

            val ownerKeyId = resolveOwnerKeyId(callingUid, descriptor) ?: run {
                return@runCatching TransactionResult.ContinueAndSkipPost
            }

            val removed = KeyMintSecurityLevelInterceptor.revokeSoftwareGrant(ownerKeyId, granteeUid)
            SystemLogger.info(
                "[TX_ID: $txId] Revoked software grants for $ownerKeyId -> uid=$granteeUid count=$removed"
            )
            InterceptorUtils.createSuccessReply(writeResultCode = false)
        }.getOrElse {
            SystemLogger.error("[TX_ID: $txId] Failed to handle ungrant", it)
            TransactionResult.ContinueAndSkipPost
        }
    }

    private fun resolveOwnerKeyId(callingUid: Int, descriptor: KeyDescriptor): KeyIdentifier? {
        return when (descriptor.domain) {
            Domain.APP -> descriptor.alias?.let { alias ->
                val kid = KeyIdentifier(callingUid, alias)
                if (KeyMintSecurityLevelInterceptor.getGeneratedKeyResponse(kid) != null) kid else null
            }
            Domain.KEY_ID -> KeyMintSecurityLevelInterceptor
                .findGeneratedOwnerKeyByKeyId(callingUid, descriptor.nspace)
            else -> null
        }
    }
}
