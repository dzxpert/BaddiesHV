/*
 * entry.c — BaddiesHV Driver Entry and Unload
 *
 * DriverEntry:
 *   1. Check SVM hardware support
 *   2. Subvert all logical processors into the VMRUN loop
 *   3. No IoCreateDevice — all communication via magic CPUID hypercall
 *
 * DriverUnload:
 *   1. Devirtualize all processors via flag polling
 *   2. Free all resources
 *
 * No device objects. No IOCTL surface. Zero driver object footprint
 * beyond the loader itself.
 */

#include "../shared/hvcomm.h"
#include "svm.h"

#define HV_LOG(fmt, ...) DbgPrint("[BaddiesHV] " fmt "\n", ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...) DbgPrint("[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 *  DriverUnload — Called when the driver is unloaded
 *
 *  Devirtualizes all processors and frees resources.
 *  If called before successful subversion, this is a no-op.
 * ============================================================================
 */

static VOID BhvDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  HV_LOG("DriverUnload — shutting down alloc worker...");
  HvAllocWorkerShutdown();

  HV_LOG("DriverUnload — beginning devirtualize...");
  SvmDevirtualizeAllProcessors();
  HV_LOG("DriverUnload — complete. BaddiesHV unloaded.");
}

/* ============================================================================
 *  DriverEntry — Main entry point
 *
 *  Flow:
 *    1. Check SVM hardware support (CPUID + MSR)
 *    2. Subvert all processors into VMRUN loops
 *    3. Return STATUS_SUCCESS (driver stays loaded)
 *
 *  On failure at any step, clean up and return the appropriate error.
 * ============================================================================
 */

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  NTSTATUS status;

  HV_LOG("========================================");
  HV_LOG("  BaddiesHV v1.0 — AMD SVM Hypervisor  ");
  HV_LOG("  Phase 1: SVM Bootstrap                ");
  HV_LOG("========================================");

  /*
   * Register unload handler only for legitimate (service-based) loads.
   * When manually mapped via KDMapper, DriverObject belongs to the
   * exploited Intel driver — we must NOT touch it.
   * Detection: RegistryPath is NULL when manually mapped.
   */
  if (RegistryPath && RegistryPath->Length > 0) {
    DriverObject->DriverUnload = BhvDriverUnload;
    HV_LOG("Unload handler registered (service-based load)");
  } else {
    HV_LOG(
        "Manual mapping detected — no unload handler (use DEVIRT hypercall)");
  }

  /* Step 1: Check hardware support */
  HV_LOG("Step 1: Checking SVM hardware support...");
  status = SvmCheckSupport();
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("SVM hardware check failed (0x%08X)", status);
    return status;
  }
  HV_LOG("Step 1: PASSED — SVM hardware supported");

  /* Step 2: Subvert all processors */
  HV_LOG("Step 2: Subverting all processors...");
  status = SvmSubvertAllProcessors();
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("Processor subversion failed (0x%08X)", status);
    /* SvmSubvertAllProcessors handles its own cleanup on failure */
    return status;
  }
  HV_LOG("Step 2: PASSED — All processors subverted");

  /* Step 3: Start alloc worker thread */
  HV_LOG("Step 3: Starting alloc worker thread...");
  status = HvAllocWorkerInit();
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("Alloc worker init failed (0x%08X) — injection unavailable",
                 status);
    /* Non-fatal — HV still works for R/W, just can't alloc */
  } else {
    HV_LOG("Step 3: PASSED — Alloc worker thread active");
  }

  HV_LOG("========================================");
  HV_LOG("  BaddiesHV is ACTIVE                   ");
  HV_LOG("  Hypercall: CPUID EAX=0x%08X       ", HV_CPUID_LEAF);
  HV_LOG("========================================");

  return STATUS_SUCCESS;
}
