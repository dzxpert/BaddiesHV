/*
 * loader.cpp — BaddiesHV Usermode Loader
 *
 * Phase 1 responsibilities:
 *   1. Load the HV driver (placeholder — actual loading via KDMapper is
 * separate)
 *   2. Issue CPUID-based hypercalls to verify the HV is active
 *   3. Test ping/echo on all logical processors
 *   4. Devirtualize (unload) the HV on user command
 *
 * Phase 4 additions (future):
 *   - Shared page allocation + registration
 *   - HvRead/HvWrite wrappers for BaddiesEAC integration
 */

#include "../shared/hvcomm.h"
#include <intrin.h>
#include <stdio.h>
#include <windows.h>

/* ============================================================================
 *  Hypercall Wrappers
 * ============================================================================
 */

/*
 * HvPing — Send a PING hypercall to the HV on the current core.
 *
 * Returns TRUE if the HV is active on this core.
 * The HV responds with EAX = HV_CPUID_LEAF, EBX = 1 (success).
 */
static bool HvPing(UINT32 *outCoreIndex) {
  int regs[4] = {0}; /* EAX, EBX, ECX, EDX */

  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_PING);

  if ((UINT32)regs[0] == HV_CPUID_LEAF && (UINT32)regs[1] == 1) {
    if (outCoreIndex)
      *outCoreIndex = (UINT32)regs[2]; /* ECX = processor index */
    return true;
  }

  return false;
}

/*
 * HvDevirtualize — Signal the HV to devirtualize all processors.
 */
static bool HvDevirtualize() {
  int regs[4] = {0};

  __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_DEVIRT);

  return ((UINT32)regs[0] == HV_CPUID_LEAF && (UINT32)regs[1] == 1);
}

/* ============================================================================
 *  Core Affinity Helpers
 * ============================================================================
 */

/*
 * PinThreadToCore — Set the current thread's affinity to a single core.
 *
 * Returns the previous affinity mask.
 */
static DWORD_PTR PinThreadToCore(DWORD coreIndex) {
  DWORD_PTR mask = (DWORD_PTR)1 << coreIndex;
  return SetThreadAffinityMask(GetCurrentThread(), mask);
}

/* ============================================================================
 *  Test Functions
 * ============================================================================
 */

/*
 * TestPingAllCores — Ping the HV on every logical processor.
 *
 * For the Phase 1 gate test, we need every core to respond.
 * Returns the number of cores that responded.
 */
static UINT32 TestPingAllCores() {
  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  DWORD numCores = sysInfo.dwNumberOfProcessors;

  printf("[*] Testing PING hypercall on %lu cores...\n", numCores);

  UINT32 respondedCount = 0;
  DWORD_PTR oldAffinity = 0;

  for (DWORD i = 0; i < numCores; i++) {
    oldAffinity = PinThreadToCore(i);

    UINT32 reportedCore = 0;
    bool success = HvPing(&reportedCore);

    if (success) {
      printf("  [+] Core %2lu: HV active (reported core %u)\n", i,
             reportedCore);
      respondedCount++;
    } else {
      printf("  [-] Core %2lu: HV NOT ACTIVE\n", i);
    }

    /* Restore affinity */
    SetThreadAffinityMask(GetCurrentThread(), oldAffinity);
  }

  printf("[*] Result: %u / %lu cores responded\n", respondedCount, numCores);
  return respondedCount;
}

/*
 * TestDevirtualize — Signal devirtualize and verify all cores exited.
 */
static void TestDevirtualize() {
  printf("\n[*] Sending DEVIRT hypercall...\n");

  bool result = HvDevirtualize();
  if (result) {
    printf("[+] Devirtualize acknowledged\n");
  } else {
    printf("[-] Devirtualize failed or HV not active\n");
    return;
  }

  /* Give the HV time to devirtualize all cores */
  printf("[*] Waiting 2 seconds for all cores to exit...\n");
  Sleep(2000);

  /* Verify: ping should now fail on all cores */
  printf("[*] Verifying devirtualize — pinging all cores...\n");
  UINT32 stillActive = TestPingAllCores();

  if (stillActive == 0) {
    printf("[+] SUCCESS: All cores devirtualized cleanly!\n");
  } else {
    printf("[!] WARNING: %u cores still active after devirtualize!\n",
           stillActive);
  }
}

/* ============================================================================
 *  Main
 * ============================================================================
 */

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  printf("========================================\n");
  printf("  BaddiesHV Loader v1.0                 \n");
  printf("  Phase 1: SVM Bootstrap Test           \n");
  printf("========================================\n\n");

  /* Check if HV is loaded by pinging the current core first */
  printf("[*] Quick check: pinging HV on current core...\n");
  UINT32 coreIdx = 0;
  if (!HvPing(&coreIdx)) {
    printf("[-] HV is NOT active on current core.\n");
    printf("    Make sure the driver is loaded first (via KDMapper or "
           "similar).\n");
    printf("\n    Usage:\n");
    printf("      1. Load BaddiesHV-Driver.sys using KDMapper\n");
    printf("      2. Run this loader to test hypercalls\n");
    printf("      3. Use menu option to devirtualize when done\n\n");
    return 1;
  }
  printf("[+] HV is active on current core (core %u)\n\n", coreIdx);

  /* Interactive menu */
  while (true) {
    printf("\n--- BaddiesHV Test Menu ---\n");
    printf("  1. Ping all cores\n");
    printf("  2. Devirtualize (unload HV)\n");
    printf("  3. Exit loader (HV stays active)\n");
    printf("  > ");

    int choice = 0;
    if (scanf_s("%d", &choice) != 1) {
      /* Clear invalid input */
      int c;
      while ((c = getchar()) != '\n' && c != EOF)
        ;
      continue;
    }

    switch (choice) {
    case 1:
      printf("\n");
      TestPingAllCores();
      break;

    case 2:
      TestDevirtualize();
      printf("\nDevirtualize complete. Exiting...\n");
      return 0;

    case 3:
      printf("\nExiting loader — HV remains active.\n");
      printf("Run this loader again to test or devirtualize.\n");
      return 0;

    default:
      printf("Invalid choice. Try again.\n");
      break;
    }
  }

  return 0;
}
