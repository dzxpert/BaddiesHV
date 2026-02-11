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


#define HV_LOG(fmt, ...)                                                       \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BaddiesHV] " fmt "\n",  \
             ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...)                                                 \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                          \
             "[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 *  DriverUnload — Called when the driver is unloaded
 *
 *  Devirtualizes all processors and frees resources.
 *  If called before successful subversion, this is a no-op.
 * ============================================================================
 */

static VOID BhvDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

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
  UNREFERENCED_PARAMETER(RegistryPath);
  NTSTATUS status;

  HV_LOG("========================================");
  HV_LOG("  BaddiesHV v1.0 — AMD SVM Hypervisor  ");
  HV_LOG("  Phase 1: SVM Bootstrap                ");
  HV_LOG("========================================");

  /* Register unload handler */
  DriverObject->DriverUnload = BhvDriverUnload;

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

  HV_LOG("========================================");
  HV_LOG("  BaddiesHV is ACTIVE                   ");
  HV_LOG("  Hypercall: CPUID EAX=0x%08X       ", HV_CPUID_LEAF);
  HV_LOG("========================================");

  return STATUS_SUCCESS;
}
