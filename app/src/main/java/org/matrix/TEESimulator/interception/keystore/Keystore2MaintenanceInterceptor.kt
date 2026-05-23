package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.maintenance.IKeystoreMaintenance
import android.system.keystore2.Domain
import android.system.keystore2.KeyDescriptor
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Interceptor for `IKeystoreMaintenance` (`android.security.maintenance` service) on
 * Android S and newer.
 *
 * The maintenance interface lives in the same `keystore2` process as `IKeystoreService` and is the
 * only entry point that can purge or rename keys *without* going through `IKeystoreService.getKeyEntry`
 * / `deleteKey`. If we don't intercept it, a detection probe can call `deleteAllKeys()` or
 * `clearNamespace(APP, uid)` and observe a state divergence: real keystore2 forgets every key, but
 * `KeyMintSecurityLevelInterceptor.generatedKeys` still serves the cached patched chain on the next
 * `getKeyEntry` — a structural cross-API inconsistency that any future probe can exploit.
 *
 * Defensive contract: every maintenance call that destroys or moves software-keyed state in real
 * keystore2 also destroys or moves the matching entries in our software-key caches, then forwards
 * the call so real keystore2 still does its work for hardware-backed keys.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object Keystore2MaintenanceInterceptor : BinderInterceptor() {

    private val stubClass = IKeystoreMaintenance.Stub::class.java

    private val CLEAR_NAMESPACE_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "clearNamespace")
    private val DELETE_ALL_KEYS_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "deleteAllKeys")
    private val ON_USER_REMOVED_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "onUserRemoved")
    private val MIGRATE_KEY_NAMESPACE_TRANSACTION =
        InterceptorUtils.getTransactCode(stubClass, "migrateKeyNamespace")

    private val transactionNames: Map<Int, String> by lazy {
        stubClass.declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    val INTERCEPTED_CODES: IntArray by lazy {
        listOfNotNull(
            CLEAR_NAMESPACE_TRANSACTION.takeIf { it != -1 },
            DELETE_ALL_KEYS_TRANSACTION.takeIf { it != -1 },
            ON_USER_REMOVED_TRANSACTION.takeIf { it != -1 },
            MIGRATE_KEY_NAMESPACE_TRANSACTION.takeIf { it != -1 },
        ).toIntArray()
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
        return when (code) {
            DELETE_ALL_KEYS_TRANSACTION -> {
                logTransaction(txId, "deleteAllKeys", callingUid, callingPid)
                // Synchronously drop ALL software-key state. The actual keystore2 daemon
                // is still about to do the same; we stay one step ahead so any racing
                // getKeyEntry from the same probe cannot observe a stale cache.
                runCatching {
                    KeyMintSecurityLevelInterceptor.clearAllGeneratedKeys(
                        reason = "IKeystoreMaintenance.deleteAllKeys"
                    )
                }.onFailure {
                    SystemLogger.error("[TX_ID: $txId] clearAllGeneratedKeys threw; forwarding anyway", it)
                }
                TransactionResult.ContinueAndSkipPost
            }

            CLEAR_NAMESPACE_TRANSACTION -> {
                logTransaction(txId, "clearNamespace", callingUid, callingPid)
                runCatching {
                    data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
                    val domain = data.readInt()
                    val nspace = data.readLong()
                    handleClearNamespace(txId, domain, nspace)
                }.onFailure {
                    SystemLogger.error("[TX_ID: $txId] clearNamespace handler threw; forwarding anyway", it)
                }
                TransactionResult.ContinueAndSkipPost
            }

            ON_USER_REMOVED_TRANSACTION -> {
                logTransaction(txId, "onUserRemoved", callingUid, callingPid)
                runCatching {
                    data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
                    val userId = data.readInt()
                    handleUserRemoved(txId, userId)
                }.onFailure {
                    SystemLogger.error("[TX_ID: $txId] onUserRemoved handler threw; forwarding anyway", it)
                }
                TransactionResult.ContinueAndSkipPost
            }

            MIGRATE_KEY_NAMESPACE_TRANSACTION -> {
                logTransaction(txId, "migrateKeyNamespace", callingUid, callingPid)
                runCatching {
                    data.enforceInterface(IKeystoreMaintenance.DESCRIPTOR)
                    val source = data.readTypedObject(KeyDescriptor.CREATOR)
                    val destination = data.readTypedObject(KeyDescriptor.CREATOR)
                    handleMigrate(txId, callingUid, source, destination)
                }.onFailure {
                    SystemLogger.error("[TX_ID: $txId] migrateKeyNamespace handler threw; forwarding anyway", it)
                }
                TransactionResult.ContinueAndSkipPost
            }

            else -> {
                logTransaction(
                    txId,
                    transactionNames[code] ?: "unknown code=$code",
                    callingUid,
                    callingPid,
                    true,
                )
                TransactionResult.ContinueAndSkipPost
            }
        }
    }

    private fun handleClearNamespace(txId: Long, domain: Int, nspace: Long) {
        when (domain) {
            Domain.APP -> {
                // Domain.APP nspace = the target UID per AOSP keystore2 semantics.
                val targetUid = nspace.toInt()
                val keys = KeyMintSecurityLevelInterceptor.generatedKeys.keys
                    .filter { it.uid == targetUid }
                    .toList()
                keys.forEach { KeyMintSecurityLevelInterceptor.cleanupKeyData(it) }
                if (keys.isNotEmpty()) {
                    SystemLogger.info(
                        "[TX_ID: $txId] clearNamespace(APP, uid=$targetUid) dropped ${keys.size} software keys."
                    )
                }
            }

            Domain.SELINUX -> {
                // Domain.SELINUX namespaces never contain software-generated keys (we only
                // track Domain.APP-scoped aliases). Forward to the real daemon and exit.
                SystemLogger.debug(
                    "[TX_ID: $txId] clearNamespace(SELINUX, $nspace): no software-key state affected."
                )
            }

            else -> {
                SystemLogger.debug(
                    "[TX_ID: $txId] clearNamespace(domain=$domain, $nspace): unsupported domain, forwarding."
                )
            }
        }
    }

    private fun handleUserRemoved(txId: Long, userId: Int) {
        // AOSP UID-to-user mapping: uid / 100000 == userId. Drop every cached software key for
        // any UID owned by the removed user.
        val userIdRange = (userId * USER_HANDLE_RANGE_PER_USER) until ((userId + 1) * USER_HANDLE_RANGE_PER_USER)
        val keys = KeyMintSecurityLevelInterceptor.generatedKeys.keys
            .filter { it.uid in userIdRange }
            .toList()
        keys.forEach { KeyMintSecurityLevelInterceptor.cleanupKeyData(it) }
        if (keys.isNotEmpty()) {
            SystemLogger.info(
                "[TX_ID: $txId] onUserRemoved(userId=$userId) dropped ${keys.size} software keys."
            )
        }
    }

    private fun handleMigrate(
        txId: Long,
        callingUid: Int,
        source: KeyDescriptor?,
        destination: KeyDescriptor?,
    ) {
        if (source == null || destination == null) return
        val sourceKeyId = resolveOwnerKeyId(callingUid, source) ?: return
        // Migration semantics: source disappears, destination appears with the same backing
        // key material. For software-only keys we just rename the cache entry.
        val info = KeyMintSecurityLevelInterceptor.generatedKeys[sourceKeyId] ?: return
        val targetAlias = destination.alias
        if (targetAlias.isNullOrEmpty() || destination.domain != Domain.APP) {
            // Real keystore2 only accepts APP/SELINUX targets. Software-key cache is keyed by
            // (uid, alias), so a non-APP target cannot have a 1:1 mapping. Drop and forward —
            // the daemon will do the right thing for any non-software-backed source.
            KeyMintSecurityLevelInterceptor.cleanupKeyData(sourceKeyId)
            SystemLogger.info(
                "[TX_ID: $txId] migrateKeyNamespace dropped software cache for $sourceKeyId (non-APP target)."
            )
            return
        }
        val newKeyId = KeyIdentifier(callingUid, targetAlias)
        KeyMintSecurityLevelInterceptor.generatedKeys[newKeyId] = info
        KeyMintSecurityLevelInterceptor.cleanupKeyData(sourceKeyId)
        SystemLogger.info(
            "[TX_ID: $txId] migrateKeyNamespace renamed software cache $sourceKeyId -> $newKeyId."
        )
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

    /** Standard AOSP `UserHandle.PER_USER_RANGE = 100_000`. */
    private const val USER_HANDLE_RANGE_PER_USER = 100_000
}
