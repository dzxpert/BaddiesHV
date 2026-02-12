# BaddiesHV

**A stealth AMD-V hypervisor with anti-cheat evasion capabilities**

BaddiesHV is a research-focused, thin AMD SVM (Secure Virtual Machine) hypervisor designed for low-level system interaction and anti-cheat analysis. It provides kernel-mode memory access primitives via CPUID-based hypercalls and includes a complete DLL injection pipeline with DX11 overlay support.

> ⚠️ **Educational Purpose Only**: This project is intended for security research and educational purposes. Use responsibly and only on systems you own or have explicit permission to test.

---

## 🎯 Features

### Core Hypervisor (BaddiesHV-Driver)
- **AMD SVM Virtualization**: Full AMD-V hardware virtualization with VMCB management
- **Nested Page Tables (NPT)**: Identity-mapped physical memory with 2MB large pages
- **NPT-Based Protection**: Hypervisor structures (VMCB, MSRPM, Host Save Area) marked non-present to prevent detection
- **CPUID Hypercall Interface**: Stealth communication via magic CPUID leaf (`0xBADD1E5`) - no VMMCALL detection vector
- **CR3 Cache**: Efficient process CR3 discovery via EPROCESS linked list walk
- **Dynamic Offset Discovery**: Runtime Windows structure offset detection for cross-version compatibility (Win10/11)
- **Safe Memory Operations**: Page-fault-safe kernel VA reads using manual page table walks
- **Deferred Allocation Worker**: PASSIVE_LEVEL thread for kernel API calls (ZwAllocateVirtualMemory, etc.)

### Stealth & Anti-Detection
- **CPUID Filtering**: Spoofs hypervisor presence bits (CPUID.01h.ECX[31], CPUID.8000_000Ah)
- **MSR Interception**: Shadows EFER.SVME bit, hides VM_HSAVE_PA
- **VMMCALL Injection**: Injects #UD on VMMCALL to mimic bare-metal behavior
- **Zero Driver Footprint**: No device objects, no IOCTL surface - only hypercall interface
- **NPF Handler**: Handles nested page faults for protected hypervisor memory

### Memory Access Primitives
- **Read/Write Process Memory**: Direct CR3-swap based access to any process
- **Module Base Discovery**: PEB walk with DJB2 hash-based module lookup
- **RWX Allocation**: Allocate executable memory in target processes
- **Safe Read/Write**: Deferred operations for file-backed pages (handles page faults gracefully)

### Loader & Injection (BaddiesHV-Loader)
- **KDMapper Integration**: Manual driver mapping via Intel vulnerability exploit
- **Shared Page Protocol**: 4KB shared memory for hypercall data exchange
- **Full PE Injection Pipeline**:
  - Export cache system (batch reads all exports to minimize VMEXITs)
  - Import resolution with hash-based lookups
  - Relocation processing
  - TLS callback execution
  - Position-independent shellcode generation

### DX11 Overlay (BaddiesHV-Overlay)
- **ImGui Integration**: Full-featured immediate-mode GUI
- **IDXGISwapChain::Present Hook**: 14-byte absolute jump inline hook
- **WndProc Hooking**: Input capture for menu interaction
- **Dark Theme**: Cyan-accented dark UI theme
- **Hot Keys**: INSERT (toggle menu), END (unhook and unload)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Guest OS (Windows)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ BaddiesHV-   │  │ BaddiesHV-   │  │  Target      │      │
│  │   Loader     │  │   Overlay    │  │  Process     │      │
│  │  (usermode)  │  │  (injected)  │  │ (e.g. game)  │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                  │               │
│         └─────────────────┴──────────────────┘               │
│                           │                                  │
│                    CPUID 0xBADD1E5                          │
│                    (Hypercall Interface)                     │
└─────────────────────────────┬───────────────────────────────┘
                              │ VMEXIT
┌─────────────────────────────▼───────────────────────────────┐
│              BaddiesHV Hypervisor (VMX Root)                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  VMEXIT Handler (svm.c)                              │   │
│  │  ├─ CPUID → Hypercall Dispatcher                     │   │
│  │  ├─ MSR   → EFER.SVME shadowing, VM_HSAVE_PA hiding  │   │
│  │  ├─ NPF   → Hypervisor structure protection          │   │
│  │  ├─ NMI   → Re-injection                             │   │
│  │  └─ VMMCALL → #UD injection (anti-detection)         │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Memory Operations (mem_ops.c)                       │   │
│  │  ├─ HvTranslateGuestVa (manual page table walk)      │   │
│  │  ├─ HvCacheCr3 (EPROCESS linked list walk)           │   │
│  │  ├─ HvReadProcessMemory / HvWriteProcessMemory       │   │
│  │  └─ HvFindModuleBase (PEB walk + DJB2 hash)          │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  NPT Management (npt.c, npt_protection.c)            │   │
│  │  ├─ Identity map builder (2MB large pages)           │   │
│  │  └─ NptProtectHypervisorStructures                   │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Allocation Worker (alloc_worker.c)                  │   │
│  │  └─ Deferred ZwAllocateVirtualMemory (PASSIVE_LEVEL) │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 Requirements

### Hardware
- **AMD CPU** with SVM support (AMD-V virtualization)
- SVM not locked by BIOS (VM_CR.SVMDIS = 0)
- NPT (Nested Page Tables) support
- CPUID filter bitmap support

### Software
- **Windows 10/11** (x64)
  - Tested on Windows 10 21H2, 22H2
  - Tested on Windows 11 23H2
- **Visual Studio 2019/2022** with:
  - Windows Driver Kit (WDK)
  - C++ Desktop Development
  - Spectre-mitigated libraries
- **Test Mode** or **Vulnerable Driver** for KDMapper

---

## 🚀 Building

### Option 1: Visual Studio (Recommended)
1. Open `BaddiesHV.sln` in Visual Studio
2. Set configuration to **Release | x64**
3. Build Solution (Ctrl+Shift+B)

Output files:
- `BaddiesHV-Driver\x64\Release\BaddiesHV-Driver.sys`
- `BaddiesHV-Loader\x64\Release\BaddiesHV-Loader.exe`
- `BaddiesHV-Overlay\x64\Release\BaddiesHV-Overlay.dll`

### Option 2: MSBuild (Command Line)
```powershell
# Build driver
msbuild BaddiesHV-Driver\BaddiesHV-Driver.vcxproj /p:Configuration=Release /p:Platform=x64

# Build loader
msbuild BaddiesHV-Loader\BaddiesHV-Loader.vcxproj /p:Configuration=Release /p:Platform=x64

# Build overlay
msbuild BaddiesHV-Overlay\BaddiesHV-Overlay.vcxproj /p:Configuration=Release /p:Platform=x64
```

---

## 🎮 Usage

### 1. Load the Hypervisor
```powershell
# Run as Administrator
.\BaddiesHV-Loader.exe
```

**Loader Menu:**
```
========================================
  BaddiesHV Loader v1.0
========================================
1. Load driver (KDMapper)
2. Ping hypervisor (all cores)
3. Register shared page
4. Test read memory
5. Test write memory
6. Test get CR3
7. Inject DLL into process
8. Devirtualize (unload HV)
9. Exit
========================================
```

### 2. Verify Hypervisor is Active
Select option **2** to ping all CPU cores. Expected output:
```
[+] Pinging all cores...
[+] Core 0: HV active
[+] Core 1: HV active
...
[+] All 12 cores virtualized successfully!
```

### 3. Register Shared Page
Select option **3** to register the shared memory page for hypercalls.

### 4. Inject Overlay
Select option **7**, then:
1. Enter target process name (e.g., `r5apex.exe`)
2. Overlay DLL will be injected and hooked to Present

### 5. Interact with Overlay
- **INSERT** - Toggle menu visibility
- **END** - Unhook and unload overlay

### 6. Unload Hypervisor
Select option **8** to devirtualize all processors and unload.

---

## 🔬 Hypercall API

### Shared Page Registration
```c
// Two-step VA registration via CPUID ECX encoding
__cpuidex(regs, HV_CPUID_LEAF, (va_low << 8) | HV_CMD_REGISTER_LO);
__cpuidex(regs, HV_CPUID_LEAF, (va_high << 8) | HV_CMD_REGISTER_HI);
```

### Read Process Memory
```c
g_SharedPage->request.magic = HV_MAGIC;
g_SharedPage->request.command = HV_CMD_READ;
g_SharedPage->request.pid = targetPid;
g_SharedPage->request.address = targetVA;
g_SharedPage->request.size = bytesToRead;

__cpuidex(regs, HV_CPUID_LEAF, HV_CMD_READ);

// Data is now in g_SharedPage->data[]
memcpy(buffer, g_SharedPage->data, bytesToRead);
```

### Write Process Memory
```c
memcpy(g_SharedPage->data, buffer, bytesToWrite);

g_SharedPage->request.magic = HV_MAGIC;
g_SharedPage->request.command = HV_CMD_WRITE;
g_SharedPage->request.pid = targetPid;
g_SharedPage->request.address = targetVA;
g_SharedPage->request.size = bytesToWrite;

__cpuidex(regs, HV_CPUID_LEAF, HV_CMD_WRITE);
```

### Allocate RWX Memory
```c
g_SharedPage->request.magic = HV_MAGIC;
g_SharedPage->request.command = HV_CMD_ALLOC;
g_SharedPage->request.pid = targetPid;
g_SharedPage->request.size = allocationSize;

__cpuidex(regs, HV_CPUID_LEAF, HV_CMD_ALLOC);

// Poll until complete
while (g_SharedPage->status == HV_SHARED_STATUS_PENDING) {
    Sleep(1);
}

uint64_t allocatedBase = g_SharedPage->request.address;
```

### Get Process CR3
```c
g_SharedPage->request.magic = HV_MAGIC;
g_SharedPage->request.command = HV_CMD_GET_CR3;
g_SharedPage->request.pid = targetPid;

__cpuidex(regs, HV_CPUID_LEAF, HV_CMD_GET_CR3);

uint64_t cr3 = g_SharedPage->request.result;
```

### Find Module Base
```c
uint64_t moduleHash = Djb2HashWide(L"ntdll.dll");

g_SharedPage->request.magic = HV_MAGIC;
g_SharedPage->request.command = HV_CMD_FIND_MODULE;
g_SharedPage->request.pid = targetPid;
g_SharedPage->request.address = moduleHash;

__cpuidex(regs, HV_CPUID_LEAF, HV_CMD_FIND_MODULE);

uint64_t moduleBase = g_SharedPage->request.result;
```

---

## 🛡️ Anti-Cheat Considerations

### What This Hypervisor Does
✅ **Stealth Features:**
- CPUID spoofing (hides hypervisor presence bits)
- EFER.SVME shadowing (hides SVM enable bit)
- VM_HSAVE_PA hiding (hides host save area MSR)
- NPT protection (hides hypervisor structures from memory scans)
- VMMCALL → #UD injection (mimics bare-metal behavior)
- No driver object footprint (no device, no IOCTL)
- CPUID-based hypercalls (no VMMCALL detection vector)

### What This Hypervisor Does NOT Do
❌ **Known Detection Vectors:**
- **Timing attacks**: VMEXIT overhead is measurable (RDTSC/RDTSCP deltas)
- **TLB flushing**: NPT causes additional TLB pressure
- **Cache behavior**: Hypervisor memory access patterns differ from bare metal
- **CPUID latency**: Magic leaf CPUID is slower than normal CPUID
- **Interrupt latency**: GIF=0 periods during VMEXIT handling
- **MSR bitmap**: Some MSRs may have different access patterns
- **Descriptor table checks**: GDTR/IDTR may reveal hypervisor presence

### Tested Against
- ✅ **EasyAntiCheat (EAC)**: Basic functionality works, but advanced detection may trigger
- ⚠️ **BattlEye**: Not extensively tested
- ⚠️ **Vanguard (Riot)**: Likely detectable via timing/cache analysis

> **Note**: This is a research project. Modern anti-cheat systems employ sophisticated detection techniques including timing analysis, cache probing, and behavioral heuristics. Do not expect this to be undetectable in production environments.

---

## 📁 Project Structure

```
BaddiesHV/
├── BaddiesHV-Driver/          # Kernel-mode hypervisor driver
│   ├── entry.c                # Driver entry point
│   ├── svm.c / svm.h          # SVM lifecycle & VMEXIT handler
│   ├── mem_ops.c              # Memory operations (CR3 cache, R/W)
│   ├── npt.c / npt.h          # NPT identity map builder
│   ├── npt_protection.c/h     # NPT-based hypervisor protection
│   ├── offset_discovery.c/h   # Dynamic Windows offset discovery
│   ├── alloc_worker.c         # Deferred allocation worker thread
│   └── svm_asm.asm            # Assembly stubs (VMRUN, host state)
│
├── BaddiesHV-Loader/          # Usermode loader & injector
│   ├── loader.cpp             # Main loader (KDMapper + hypercall tests)
│   ├── injector.cpp           # PE manual mapper
│   └── kdmapper/              # KDMapper integration (Intel vuln exploit)
│
├── BaddiesHV-Overlay/         # DX11 overlay DLL
│   ├── dllmain.cpp            # DLL entry, Present hook, ImGui rendering
│   └── imgui/                 # ImGui library
│
└── shared/
    └── hvcomm.h               # Shared hypercall protocol definitions
```

---

## 🧪 Testing & Verification

### Hardware Support Check
```powershell
# Check for AMD-V support
wmic cpu get name,virtualizationfirmwareenabled

# Check CPUID for SVM
# CPUID.8000_0001h.ECX[2] should be 1
```

### Driver Logs
View hypervisor logs via DebugView or WinDbg:
```
[BaddiesHV] ========================================
[BaddiesHV]   BaddiesHV v1.0 — AMD SVM Hypervisor
[BaddiesHV]   Phase 1: SVM Bootstrap
[BaddiesHV] ========================================
[BaddiesHV] Step 1: Checking SVM hardware support...
[BaddiesHV] Step 1: PASSED — SVM hardware supported
[BaddiesHV] Step 2: Subverting all processors...
[BaddiesHV] Step 2: PASSED — All processors subverted
[BaddiesHV] ========================================
[BaddiesHV]   BaddiesHV is ACTIVE
[BaddiesHV]   Hypercall: CPUID EAX=0x0BADD1E5
[BaddiesHV] ========================================
```

### Known Issues
- **BSOD on some systems**: NPT protection may cause issues on certain AMD CPU models
- **Injection failures**: Export cache may fail if target DLLs are paged out
- **Timing-based detection**: EAC may detect via RDTSC deltas during heavy VMEXIT load

---

## 🔧 Troubleshooting

### "SVM hardware check failed"
- Ensure AMD-V is enabled in BIOS
- Check that SVM is not locked (VM_CR.SVMDIS = 0)
- Verify CPU supports NPT (CPUID.8000_000Ah.EDX[0])

### "Processor subversion failed"
- Disable Hyper-V / WSL2 (conflicts with SVM)
- Check for other hypervisors (VirtualBox, VMware)
- Run on bare metal (not in a VM)

### "KDMapper failed to load driver"
- Ensure running as Administrator
- Disable Driver Signature Enforcement (test mode)
- Check that Intel vulnerable driver is available

### BSOD during injection
- Target process may have paged out DLLs
- Try using `HV_CMD_READ_SAFE` instead of `HV_CMD_READ`
- Reduce injection speed (add delays between writes)

---

## 🤝 Contributing

This is a research project. Contributions are welcome for:
- Additional stealth techniques
- Cross-platform support (Linux KVM, Intel VT-x)
- Performance optimizations
- Bug fixes and stability improvements

**Please do not:**
- Request features for bypassing specific anti-cheat systems
- Submit malicious use cases
- Distribute modified versions for commercial purposes

---

## 📜 License

This project is provided **as-is** for educational and research purposes only.

**No warranty is provided.** Use at your own risk. The authors are not responsible for any damage, detection, or bans resulting from the use of this software.

---

## 🙏 Acknowledgments

- **SimpleSvm** - Original AMD SVM hypervisor framework (forked base)
- **HyperPlatform** - Reference for NPT implementation
- **KDMapper** - Manual driver mapping technique
- **ImGui** - Immediate-mode GUI library
- **AMD** - AMD64 Architecture Programmer's Manual

---

## 📚 References

- [AMD64 Architecture Programmer's Manual Volume 2: System Programming](https://www.amd.com/system/files/TechDocs/24593.pdf)
- [SimpleSvm - A simple SVM-based hypervisor](https://github.com/tandasat/SimpleSvm)
- [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
- [KDMapper - Manual Driver Mapping](https://github.com/TheCruZ/kdmapper)

---

**⚠️ Use responsibly. This tool is for educational purposes only.**
