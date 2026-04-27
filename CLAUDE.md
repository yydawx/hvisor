# Hvisor Multiboot2 Zone1 Debug Summary

## Task Goal
Debug hvisor hypervisor to boot Asterinas OS as guest VM (zone1) using Multiboot2 protocol on x86_64.
**Reference: QEMU HVF implementation - completely replicate QEMU's correct flow and design.**

## Progress

### Working
- Zone0 (Linux kernel) boots successfully via ACPI/boot protocol

### Current Issue
Zone1 (Asterinas via Multiboot2) triple faults at RIP=0xffffffff889bf7c8

### Latest Finding (2026-04-26)
Guest page table analysis reveals:
- RIP `0xffffffff889bf7c8` is in kernel high address space
- **PDPT[0x1fe] = 0x0** - This 1GB region (0xffffffff80000000 - 0xffffffffbfffffff) is NOT mapped
- **IDTR base=0x0, limit=0xffff** - Guest has no IDT set up
- CR3=0x11848000, CR4=0x12620, EFER=0xd00 (LMA=1, NXE=1)
- PML4[0x1ff] = 0x1600f8007 (valid entry)

The guest kernel's page tables do not map the high address where it's trying to execute.

## Errors Fixed

### 1. EFER.LME Bit Check Error
- **Problem**: Was checking bit 10 instead of bit 8
- **Fix**: EFER.LME is bit 8, LMA is bit 10
- **File**: `src/arch/x86_64/trap.rs`

### 2. Exception Re-injection Error Code
- **Problem**: Reading error code from EXIT_QUALIFICATION
- **Fix**: Use `int_info.err_code` from VMEXIT_INTERRUPTION_ERR_CODE
- **File**: `src/arch/x86_64/trap.rs`

### 3. Exception Bitmap Setting
- **Problem**: zone0 (Linux) failing with #PF after exception_bitmap change
- **Fix**: Set exception_bitmap to 0 (like QEMU: `wvmcs(fd, VMCS_EXCEPTION_BITMAP, 0)`)
- **File**: `src/arch/x86_64/cpu.rs:558`

### 4. CR4 Handling - VMXE Mask
- **Problem**: Was intercepting PGE/PAE/PCIDE/SMEP bits, preventing guest TLB flush
- **QEMU Reference**: `wvmcs(vcpu, VMCS_CR4_MASK, CR4_VMXE_MASK)` - only intercept VMXE!
- **Fix**: CR4_GUEST_HOST_MASK = only bit 13 (VMXE)
- **Files**: `src/arch/x86_64/cpu.rs:636-644`, `src/arch/x86_64/trap.rs:309-338`

## QEMU Reference Implementation

### Key Files
- `/home/yyda/workspace/syswand_asterinas/qemu-9.2.3/target/i386/hvf/vmx.h`
  - `macvm_set_cr0()` - CR0 handling with EFER long mode transition
  - `macvm_set_cr4()` - CR4 handling (only mask VMXE, call `hv_vcpu_invalidate_tlb`)
  - `enter_long_mode()` - Sets EFER.LMA and VM_ENTRY_GUEST_LMA

- `/home/yyda/workspace/syswand_asterinas/qemu-9.2.3/target/i386/hvf/hvf.c`
  - Main VM exit handling loop
  - Exception bitmap = 0

- `/home/yyda/workspace/syswand_asterinas/qemu-9.2.3/target/i386/hvf/x86_emu.c`
  - MSR handling including EFER

### Key Patterns from QEMU
```c
// macvm_set_cr4 - vmx.h:164
static inline void macvm_set_cr4(hv_vcpuid_t vcpu, uint64_t cr4) {
    uint64_t guest_cr4 = cr4 | CR4_VMXE_MASK;
    wvmcs(vcpu, VMCS_GUEST_CR4, guest_cr4);
    wvmcs(vcpu, VMCS_CR4_SHADOW, cr4);
    wvmcs(vcpu, VMCS_CR4_MASK, CR4_VMXE_MASK);  // ONLY VMXE!
    hv_vcpu_invalidate_tlb(vcpu);
}

// Exception bitmap - hvf.c:311
wvmcs(cpu->accel->fd, VMCS_EXCEPTION_BITMAP, 0);
```

## Current Debug Session

### Guest State at Triple Fault
```
RIP=0xffffffff889bf7c8, RSP=0xffffffff88049ec0
CR0=0x80010033, CR3=0x11848000, CR4=0x12620, EFER=0xd00
IDTR: base=0x0, limit=0xffff (NO IDT!)
CS selector=0x8, GDTR base=0x80014f0
GS_BASE=0xffffffff88f8b000

Page table walk:
  PML4_GPA=0x11848000
  PML4[0x1ff] = 0x1600f8007 (valid)
  PDPT[0x1fe] = 0x0 (NOT MAPPED!)
```

### Analysis
1. Guest enabled long mode (EFER.LMA=1)
2. Guest set up page tables at CR3=0x11848000
3. Guest's page tables don't map the kernel high address space
4. Guest has no IDT (base=0)
5. Any exception causes immediate triple fault

### Possible Root Causes
1. **Multiboot2 kernel load address mismatch**: Kernel ELF loaded at GPA 0x8000000, but kernel expects to run at high virtual address
2. **EPT mapping issue**: Zone memory configuration maps GPA 0x0-0x200000000, but guest page tables reference HPAs outside this range
3. **Kernel page table setup incomplete**: Kernel may not have finished setting up its page tables before jumping to high address

## Configuration Files

### Zone1 Config: `/home/yyda/workspace/syswand_asterinas/zone1-asterinas.json`
```json
{
    "zone_id": 1,
    "memory_regions": [{
        "type": "ram",
        "physical_start": "0x40000000",
        "virtual_start": "0x0",
        "size": "0x200000000"
    }],
    "kernel_load_paddr": "0x40800000",
    "entry_point": "0x8001238",
    "multiboot_enabled": true
}
```

### Memory Layout
- Kernel ELF loaded at: GPA 0x8000000 (HPA 0x48000000)
- GPA->HPA offset: 0x40000000
- Guest physical: 0x0 - 0x200000000 (8GB)

## Next Steps
1. Analyze why guest page table doesn't map kernel high addresses
2. Check if Asterinas kernel expects specific memory layout for Multiboot2
3. Verify EPT mappings cover all addresses guest page tables reference
4. Consider if guest page table entries use physical addresses that need EPT translation
