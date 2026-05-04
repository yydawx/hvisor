// Copyright (c) 2025 Syswonder
// hvisor is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR
// FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//
// Syswonder Website:
//      https://www.syswonder.org
//
// Authors:
//  Solicey <lzoi_lth@163.com>

use crate::{
    arch::{
        cpu::{this_cpu_id, ArchCpu},
        cpuid::{CpuIdEax, ExtendedFeaturesEcx, FeatureInfoFlags},
        hpet,
        idt::{IdtStruct, IdtVector},
        ipi,
        msr::Msr::{self, *},
        s2pt::Stage2PageFaultInfo,
        vmcs::*,
        vmx::{VmxCrAccessInfo, VmxExitInfo, VmxExitReason, VmxInstructionError, VmxInterruptInfo, VmxInterruptionType, VmxIoExitInfo},
    },
    cpu_data::{this_cpu_data, this_zone},
    device::{
        irqchip::{
            inject_vector,
            pic::{ioapic::irqs, lapic::VirtLocalApic},
        },
        uart::{virt_console_io_read, virt_console_io_write, UartReg},
    },
    error::HvResult,
    hypercall::HyperCall,
    memory::{mmio_handle_access, HostPhysAddr, MMIOAccess, MemFlags},
    zone::this_zone_id,
};
use bit_field::BitField;
use core::mem::size_of;
use x86_64::registers::control::Cr4Flags;

use super::{
    pci::{handle_pci_config_port_read, handle_pci_config_port_write},
    pio::{PCI_CONFIG_ADDR_PORT, PCI_CONFIG_DATA_PORT, UART_COM1_PORT},
};

core::arch::global_asm!(
    include_str!("trap.S"),
    sym arch_handle_trap
);

const IRQ_VECTOR_START: u8 = 0x20;
const IRQ_VECTOR_END: u8 = 0xff;

const VM_EXIT_INSTR_LEN_CPUID: u8 = 2;
const VM_EXIT_INSTR_LEN_HLT: u8 = 1;
const VM_EXIT_INSTR_LEN_RDMSR: u8 = 2;
const VM_EXIT_INSTR_LEN_WRMSR: u8 = 2;
const VM_EXIT_INSTR_LEN_VMCALL: u8 = 3;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TrapFrame {
    pub usr: [u64; 15],

    // pushed by 'trap.S'
    pub vector: u64,
    pub error_code: u64,

    // pushed by CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

lazy_static::lazy_static! {
    static ref IDT: IdtStruct = IdtStruct::new();
}

pub fn install_trap_vector() {
    IDT.load();
}

#[no_mangle]
pub fn arch_handle_trap(tf: &mut TrapFrame) {
    // println!("trap {} @ {:#x}", tf.vector, tf.rip);
    match tf.vector as u8 {
        IRQ_VECTOR_START..=IRQ_VECTOR_END => handle_irq(tf.vector as u8),
        _ => {
            println!(
                "Unhandled exception {} (error_code = {:#x}) @ {:#x}",
                tf.vector, tf.error_code, tf.rip
            );
        }
    }
}

fn handle_irq(vector: u8) {
    match vector {
        IdtVector::VIRT_IPI_VECTOR => {
            ipi::handle_virt_ipi();
        }
        IdtVector::APIC_SPURIOUS_VECTOR
        | IdtVector::APIC_ERROR_VECTOR
        | IdtVector::APIC_TIMER_VECTOR => {}
        _ => {
            if vector >= 0x20 && this_cpu_data().arch_cpu.power_on {
                let cpu_id = this_cpu_id();
                let zone_id = this_zone_id();
                // LAPIC-local interrupts (timer, etc.) fire on whichever CPU
                // programmed the LAPIC. They belong to the CURRENT zone,
                // not zone0. Device interrupts (0x20-0xdf) always belong to
                // zone0 and must be forwarded if they arrive on a non-zone0 CPU.
                let is_lapic_local = vector >= 0xe0;
                if zone_id == 0 || is_lapic_local {
                    inject_vector(cpu_id, vector, None, false);
                } else {
                    // Forward device interrupt to zone0.
                    let zone0 = crate::zone::find_zone(0).unwrap();
                    let zone0_cpu = zone0.read().cpu_set.first_cpu().unwrap_or(0);
                    inject_vector(zone0_cpu, vector, None, false);
                }
            }
        }
    }
    unsafe { VirtLocalApic::phys_local_apic().end_of_interrupt() };
}

fn handle_cpuid(arch_cpu: &mut ArchCpu) -> HvResult {
    use raw_cpuid::{cpuid, CpuIdResult};
    // TODO: temporary hypervisor hack
    let signature = unsafe { &*("ACRNACRNACRN".as_ptr() as *const [u32; 3]) };
    let cr4_flags = Cr4Flags::from_bits_truncate(arch_cpu.cr(4) as _);
    let regs = arch_cpu.regs_mut();
    let rax: Result<CpuIdEax, u32> = (regs.rax as u32).try_into();
    let mut res: CpuIdResult = cpuid!(regs.rax, regs.rcx);

    if let Ok(function) = rax {
        res = match function {
            CpuIdEax::FeatureInfo => {
                let mut res = cpuid!(regs.rax, regs.rcx);
                let mut ecx = FeatureInfoFlags::from_bits_truncate(res.ecx as _);

                ecx.remove(FeatureInfoFlags::VMX);
                // ecx.remove(FeatureInfoFlags::TSC_DEADLINE);
                ecx.remove(FeatureInfoFlags::XSAVE);

                ecx.insert(FeatureInfoFlags::X2APIC);
                ecx.insert(FeatureInfoFlags::HYPERVISOR);
                res.ecx = ecx.bits() as _;

                let mut edx = FeatureInfoFlags::from_bits_truncate((res.edx as u64) << 32);
                // edx.remove(FeatureInfoFlags::TSC);
                res.edx = (edx.bits() >> 32) as _;

                res
            }
            CpuIdEax::StructuredExtendedFeatureInfo => {
                let mut res = cpuid!(regs.rax, regs.rcx);
                let mut ecx = ExtendedFeaturesEcx::from_bits_truncate(res.ecx as _);
                ecx.remove(ExtendedFeaturesEcx::WAITPKG);
                res.ecx = ecx.bits() as _;

                res
            }
            CpuIdEax::TimeStampCounterInfo => {
                if let Some(freq_mhz) = hpet::get_tsc_freq_mhz() {
                    CpuIdResult {
                        eax: 1,             // denominator (non-zero)
                        ebx: 1,             // numerator (non-zero)
                        ecx: freq_mhz * 1_000_000,  // crystal frequency in Hz (non-zero)
                        edx: 0,
                    }
                } else {
                    cpuid!(regs.rax, regs.rcx)
                }
            }
            CpuIdEax::ProcessorFrequencyInfo => {
                if let Some(freq_mhz) = hpet::get_tsc_freq_mhz() {
                    CpuIdResult {
                        eax: freq_mhz,
                        ebx: freq_mhz,
                        ecx: freq_mhz,
                        edx: 0,
                    }
                } else {
                    cpuid!(regs.rax, regs.rcx)
                }
            }
            CpuIdEax::HypervisorInfo => CpuIdResult {
                eax: CpuIdEax::HypervisorFeatures as u32,
                ebx: signature[0],
                ecx: signature[1],
                edx: signature[2],
            },
            CpuIdEax::HypervisorFeatures => CpuIdResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            _ => cpuid!(regs.rax, regs.rcx),
        };
    }

    trace!(
        "VM exit: CPUID({:#x}, {:#x}): {:?}",
        regs.rax,
        regs.rcx,
        res
    );
    regs.rax = res.eax as _;
    regs.rbx = res.ebx as _;
    regs.rcx = res.ecx as _;
    regs.rdx = res.edx as _;

    arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_CPUID)?;
    Ok(())
}

fn handle_cr_access(arch_cpu: &mut ArchCpu) -> HvResult {
    let cr_access_info = VmxCrAccessInfo::new()?;
    panic!(
        "VM-exit: CR{} access:\n{:#x?}",
        cr_access_info.cr_n, arch_cpu
    );

    match cr_access_info.cr_n {
        0 => {}
        _ => {}
    }

    Ok(())
}

fn handle_external_interrupt() -> HvResult {
    let int_info = VmxInterruptInfo::new()?;
    trace!("VM-exit: external interrupt: {:#x?}", int_info);
    assert!(int_info.valid);
    handle_irq(int_info.vector);
    Ok(())
}

fn handle_hypercall(arch_cpu: &mut ArchCpu) -> HvResult {
    let regs = arch_cpu.regs_mut();
    debug!(
        "VM exit: VMCALL({:#x}): {:x?}",
        regs.rax,
        [regs.rdi, regs.rsi]
    );
    let (code, arg0, arg1) = (regs.rax, regs.rdi, regs.rsi);
    let cpu_data = this_cpu_data();
    let result = match HyperCall::new(cpu_data).hypercall(code as _, arg0, arg1) {
        Ok(ret) => ret as _,
        Err(e) => {
            error!("hypercall error: {:#?}", e);
            e.code()
        }
    };
    debug!("HVC result = {}", result);
    regs.rax = result as _;

    arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_VMCALL)?;
    Ok(())
}

fn handle_io_instruction(arch_cpu: &mut ArchCpu, exit_info: &VmxExitInfo) -> HvResult {
    let io_info = VmxIoExitInfo::new()?;

    /*info!(
        "VM exit: I/O instruction @ {:#x}: {:#x?}",
        exit_info.guest_rip, io_info,
    );*/

    if io_info.is_string {
        // Handle INS/OUTS instructions
        // For OUTS: read from DS:SI/ESI and write to port
        // For INS: read from port and write to ES:DI/EDI

        let access_size = io_info.access_size as u64;
        let count = if io_info.is_repeat {
            // REP prefix: use RCX as counter
            arch_cpu.regs().rcx
        } else {
            1
        };

        // Get direction flag from RFLAGS (bit 10)
        let rflags = VmcsGuestNW::RFLAGS.read()?;
        let direction = if rflags & (1 << 10) != 0 { -1i64 } else { 1i64 };

        if io_info.is_in {
            // INS: read from port, write to ES:DI/EDI
            let mut rdi = arch_cpu.regs().rdi;
            for _ in 0..count {
                // Read from port (return 0 for unknown ports)
                let value: u32 = if UART_COM1_PORT.contains(&io_info.port) {
                    virt_console_io_read(io_info.port)
                } else {
                    0
                };

                // Write to guest memory at ES:DI
                // Note: In protected mode, ES base is in segment descriptor
                // For simplicity, assume ES base is 0 (flat model)
                let guest_addr = rdi;
                if let Ok((hpa, _, _)) = unsafe { this_zone().read().gpm.page_table_query(guest_addr as _) } {
                    unsafe {
                        match io_info.access_size {
                            1 => core::ptr::write_volatile(hpa as *mut u8, value as u8),
                            2 => core::ptr::write_volatile(hpa as *mut u16, value as u16),
                            4 => core::ptr::write_volatile(hpa as *mut u32, value),
                            _ => {}
                        }
                    }
                }

                rdi = (rdi as i64 + direction * access_size as i64) as u64;
            }
            arch_cpu.regs_mut().rdi = rdi;
        } else {
            // OUTS: read from DS:SI/ESI and write to port
            let mut rsi = arch_cpu.regs().rsi;
            for _ in 0..count {
                // Read from guest memory at DS:SI
                // Note: In protected mode, DS base is in segment descriptor
                // For simplicity, assume DS base is 0 (flat model)
                let guest_addr = rsi;
                let value: u32 = if let Ok((hpa, _, _)) = unsafe { this_zone().read().gpm.page_table_query(guest_addr as _) } {
                    unsafe {
                        match io_info.access_size {
                            1 => core::ptr::read_volatile(hpa as *const u8) as u32,
                            2 => core::ptr::read_volatile(hpa as *const u16) as u32,
                            4 => core::ptr::read_volatile(hpa as *const u32),
                            _ => 0
                        }
                    }
                } else {
                    0
                };

                // Write to port
                if UART_COM1_PORT.contains(&io_info.port) {
                    virt_console_io_write(io_info.port, value);
                }

                rsi = (rsi as i64 + direction * access_size as i64) as u64;
            }
            arch_cpu.regs_mut().rsi = rsi;
        }

        // Update RCX if REP prefix was used
        if io_info.is_repeat {
            arch_cpu.regs_mut().rcx = 0;
        }

        arch_cpu.advance_guest_rip(exit_info.exit_instruction_length as _)?;
        return Ok(());
    }
    if io_info.is_repeat {
        error!("REP prefixed I/O instructions are not supported!");
        return hv_result_err!(ENOSYS);
    }

    let mut value: u32 = 0;
    if !io_info.is_in {
        let rax = arch_cpu.regs().rax;
        value = match io_info.access_size {
            1 => rax & 0xff,
            2 => rax & 0xffff,
            4 => rax,
            _ => unreachable!(),
        } as _;

        // TODO: reconstruct
        if PCI_CONFIG_ADDR_PORT.contains(&io_info.port)
            || PCI_CONFIG_DATA_PORT.contains(&io_info.port)
        {
            handle_pci_config_port_write(&io_info, value);
        } else if UART_COM1_PORT.contains(&io_info.port) {
            virt_console_io_write(io_info.port, value);
        } else {
            /* info!(
                "unhandled port io write {:x} value: {:x}",
                io_info.port, value
            ); */
        }
    } else {
        if PCI_CONFIG_ADDR_PORT.contains(&io_info.port)
            || PCI_CONFIG_DATA_PORT.contains(&io_info.port)
        {
            value = handle_pci_config_port_read(&io_info);
        } else if UART_COM1_PORT.contains(&io_info.port) {
            value = virt_console_io_read(io_info.port);
        } else {
            // info!("unhandled port io read {:x}", io_info.port);
            value = 0x0;
        }
        let rax = &mut arch_cpu.regs_mut().rax;
        // SDM Vol. 1, Section 3.4.1.1:
        // * 32-bit operands generate a 32-bit result, zero-extended to a 64-bit result in the
        //   destination general-purpose register.
        // * 8-bit and 16-bit operands generate an 8-bit or 16-bit result. The upper 56 bits or
        //   48 bits (respectively) of the destination general-purpose register are not modified
        //   by the operation.
        match io_info.access_size {
            1 => *rax = (*rax & !0xff) | (value & 0xff) as u64,
            2 => *rax = (*rax & !0xffff) | (value & 0xffff) as u64,
            4 => *rax = value as u64,
            _ => unreachable!(),
        }
    }

    arch_cpu.advance_guest_rip(exit_info.exit_instruction_length as _)?;
    Ok(())
}

fn handle_msr_read(arch_cpu: &mut ArchCpu) -> HvResult {
    let rcx = arch_cpu.regs().rcx as u32;

    let res: HvResult<u64> = if rcx == IA32_APIC_BASE as u32 {
        let mut apic_base = unsafe { IA32_APIC_BASE.read() };
        apic_base |= 1 << 11 | 1 << 10; // report xAPIC and x2APIC enabled
        Ok(apic_base)
    } else if VirtLocalApic::msr_range().contains(&rcx) {
        if let Ok(msr) = Msr::try_from(rcx) {
            arch_cpu.virt_lapic.rdmsr(msr)
        } else {
            // MSR not in our enum but in x2APIC range — return 0 (safe default).
            Ok(0)
        }
    } else if let Ok(msr) = Msr::try_from(rcx) {
        if msr == IA32_GS_BASE {
            VmcsGuestNW::GS_BASE.read().map(|v| v as u64).map_err(|_| hv_err!(EIO))
        } else if msr == IA32_FS_BASE {
            VmcsGuestNW::FS_BASE.read().map(|v| v as u64).map_err(|_| hv_err!(EIO))
        } else {
            hv_result_err!(ENOSYS)
        }
    } else {
        hv_result_err!(ENOSYS)
    };

    match res {
        Ok(value) => {
            debug!("VM exit: RDMSR({:#x}) -> {:#x}", rcx, value);
            arch_cpu.regs_mut().rax = value & 0xffff_ffff;
            arch_cpu.regs_mut().rdx = value >> 32;
        }
        Err(e) => {
            warn!("Failed to handle RDMSR({:#x}): {:?}", rcx, e);
        }
    }

    arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_RDMSR)?;
    Ok(())
}

fn handle_msr_write(arch_cpu: &mut ArchCpu) -> HvResult {
    let rcx = arch_cpu.regs().rcx as u32;
    let value = (arch_cpu.regs().rax & 0xffff_ffff) | (arch_cpu.regs().rdx << 32);
    debug!("VM exit: WRMSR({:#x}) <- {:#x}", rcx, value);

    let msr_opt = Msr::try_from(rcx).ok();

    let res: HvResult<()> = if rcx == IA32_APIC_BASE as u32 {
        Ok(()) // ignore — guest can't change APIC mode
    } else if VirtLocalApic::msr_range().contains(&rcx) {
        if let Some(msr) = msr_opt {
            arch_cpu.virt_lapic.wrmsr(msr, value)
        } else {
            // x2APIC MSR not in our enum (e.g. SELF_IPI at 0x83F).
            // Silently ignore — the guest thinks it succeeded.
            Ok(())
        }
    } else if msr_opt == Some(IA32_TSC_DEADLINE) {
        arch_cpu.virt_lapic.wrmsr(IA32_TSC_DEADLINE, value)
    } else if msr_opt == Some(IA32_GS_BASE) {
        VmcsGuestNW::GS_BASE.write(value as usize).map_err(|_| hv_err!(EIO))
    } else if msr_opt == Some(IA32_FS_BASE) {
        VmcsGuestNW::FS_BASE.write(value as usize).map_err(|_| hv_err!(EIO))
    } else {
        hv_result_err!(ENOSYS)
    };

    if res.is_err() {
        warn!(
            "Failed to handle WRMSR({:#x}) <- {:#x}: {:?}\n{:#x?}",
            rcx, value, res, arch_cpu
        );
    }
    arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_WRMSR)?;
    Ok(())
}

fn handle_s2pt_violation(arch_cpu: &mut ArchCpu, exit_info: &VmxExitInfo) -> HvResult {
    let fault_info = Stage2PageFaultInfo::new()?;

    debug!("EPT violation at GPA {:#x}, RIP={:#x}", fault_info.fault_guest_paddr, exit_info.guest_rip);

    mmio_handle_access(&mut MMIOAccess {
        address: fault_info.fault_guest_paddr,
        size: 0,
        is_write: fault_info.access_flags.contains(MemFlags::WRITE),
        value: 0,
    })?;

    Ok(())
}

fn handle_triple_fault(arch_cpu: &mut ArchCpu, exit_info: &VmxExitInfo) -> HvResult {
    // Print more details for debugging
    info!("Triple fault details:");
    info!("  RIP={:#x}, RSP={:#x}", exit_info.guest_rip, VmcsGuestNW::RSP.read().unwrap_or(0));
    info!("  RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
          arch_cpu.regs().rax, arch_cpu.regs().rbx, arch_cpu.regs().rcx, arch_cpu.regs().rdx);
    info!("  RSI={:#x}, RDI={:#x}", arch_cpu.regs().rsi, arch_cpu.regs().rdi);
    info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}",
          VmcsGuestNW::CR0.read().unwrap_or(0),
          VmcsGuestNW::CR3.read().unwrap_or(0),
          VmcsGuestNW::CR4.read().unwrap_or(0));
    info!("  CS selector={:#x}, GDTR base={:#x}",
          VmcsGuest16::CS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::GDTR_BASE.read().unwrap_or(0));

    panic!(
        "VM exit: Triple fault @ {:#x}, instr length: {:x}\n {:#x?}",
        exit_info.guest_rip, exit_info.exit_instruction_length, arch_cpu
    );
}

/// Walk guest page tables for virtual address `vaddr` using CR3 as the PML4 base.
/// Prints the full page table hierarchy for debugging.
fn walk_guest_page_table(vaddr: usize, cr3_gpa: usize) {
    let zone = this_zone();
    let zone_guard = zone.read();

    info!("  Guest page table walk for VA {:#x} using CR3={:#x} (GPA):", vaddr, cr3_gpa);

    // PML4 index: bits 47:39
    let pml4_idx = ((vaddr >> 39) & 0x1ff) as usize;
    // PDPT index: bits 38:30
    let pdpt_idx = ((vaddr >> 30) & 0x1ff) as usize;
    // PD index: bits 29:21
    let pd_idx = ((vaddr >> 21) & 0x1ff) as usize;
    // PT index: bits 20:12
    let pt_idx = ((vaddr >> 12) & 0x1ff) as usize;

    info!("    Indices: PML4[{:#x}] PDPT[{:#x}] PD[{:#x}] PT[{:#x}]",
          pml4_idx, pdpt_idx, pd_idx, pt_idx);

    // Read PML4 entry (at CR3 GPA + index*8)
    if let Ok((pml4_hpa, _, _)) = unsafe { zone_guard.gpm.page_table_query(cr3_gpa) } {
        let pml4_entry = unsafe { core::ptr::read_volatile((pml4_hpa as *const u64).add(pml4_idx)) };
        let pml4_present = pml4_entry & 1 != 0;
        let pml4_paddr = (pml4_entry & 0x000ffffffffff000) as usize; // bits 51:12
        info!("    PML4[{:#x}] = {:#018x} (present={}, next_table_GPA={:#x})",
              pml4_idx, pml4_entry, pml4_present, pml4_paddr);

        if !pml4_present {
            info!("    *** PAGE TABLE WALK STOPPED: PML4 entry not present ***");
            return;
        }

        // Read PDPT entry
        if let Ok((pdpt_hpa, _, _)) = unsafe { zone_guard.gpm.page_table_query(pml4_paddr) } {
            let pdpt_entry = unsafe { core::ptr::read_volatile((pdpt_hpa as *const u64).add(pdpt_idx)) };
            let pdpt_present = pdpt_entry & 1 != 0;
            let pdpt_paddr = (pdpt_entry & 0x000ffffffffff000) as usize;
            let pdpt_huge = (pdpt_entry >> 7) & 1 != 0; // PS bit = 1GB page
            info!("    PDPT[{:#x}] = {:#018x} (present={}, huge_1G={}, next_GPA={:#x})",
                  pdpt_idx, pdpt_entry, pdpt_present, pdpt_huge, pdpt_paddr);

            if !pdpt_present {
                info!("    *** PAGE TABLE WALK STOPPED: PDPT entry not present ***");
                return;
            }

            if pdpt_huge {
                // 1GB page
                let phys_base = (pdpt_entry & 0xfffffc0000000000) as usize; // bits 51:30
                let offset_within_page = vaddr & 0x3fffffff; // bits 29:0
                info!("    => 1GB huge page: phys={:#x}, offset={:#x}, final_addr={:#x}",
                      phys_base, offset_within_page, phys_base | offset_within_page);
                return;
            }

            // Read PD entry
            if let Ok((pd_hpa, _, _)) = unsafe { zone_guard.gpm.page_table_query(pdpt_paddr) } {
                let pd_entry = unsafe { core::ptr::read_volatile((pd_hpa as *const u64).add(pd_idx)) };
                let pd_present = pd_entry & 1 != 0;
                let pd_paddr = (pd_entry & 0x000ffffffffff000) as usize;
                let pd_huge = (pd_entry >> 7) & 1 != 0; // PS bit = 2MB page
                info!("    PD[{:#x}] = {:#018x} (present={}, huge_2M={}, next_GPA={:#x})",
                      pd_idx, pd_entry, pd_present, pd_huge, pd_paddr);

                if !pd_present {
                    info!("    *** PAGE TABLE WALK STOPPED: PD entry not present ***");
                    return;
                }

                if pd_huge {
                    // 2MB page
                    let phys_base = (pd_entry & 0xfffffffe00000) as usize; // bits 51:21
                    let offset_within_page = vaddr & 0x1fffff; // bits 20:0
                    info!("    => 2MB huge page: phys={:#x}, offset={:#x}, final_addr={:#x}",
                          phys_base, offset_within_page, phys_base | offset_within_page);
                    return;
                }

                // Read PT entry (4KB page)
                if let Ok((pt_hpa, _, _)) = unsafe { zone_guard.gpm.page_table_query(pd_paddr) } {
                    let pt_entry = unsafe { core::ptr::read_volatile((pt_hpa as *const u64).add(pt_idx)) };
                    let pt_present = pt_entry & 1 != 0;
                    let pt_paddr = (pt_entry & 0x000ffffffffff000) as usize;
                    info!("    PT[{:#x}] = {:#018x} (present={}, page_GPA={:#x})",
                          pt_idx, pt_entry, pt_present, pt_paddr);

                    if !pt_present {
                        info!("    *** PAGE TABLE WALK STOPPED: PT entry not present ***");
                    } else {
                        let offset_within_page = vaddr & 0xfff; // bits 11:0
                        info!("    => 4KB page: phys={:#x}, offset={:#x}, final_addr={:#x}",
                              pt_paddr, offset_within_page, pt_paddr | offset_within_page);
                    }
                }
            }
        }
    } else {
        warn!("    Cannot read CR3: GPA {:#x} not mapped in EPT", cr3_gpa);
    }
    drop(zone_guard);
}

/// Dump instruction bytes at a guest RIP for debugging unknown exceptions (e.g. #UD).
fn dump_instruction_bytes(rip: usize, num_bytes: usize) {
    let zone = this_zone();
    let zone_guard = zone.read();
    if let Ok((rip_hpa, _, _)) = unsafe { zone_guard.gpm.page_table_query(rip) } {
        let mut hex = [0u8; 64];
        let mut pos = 0;
        unsafe {
            for i in 0..num_bytes.min(16) {
                let b = core::ptr::read_volatile((rip_hpa as *const u8).add(i));
                let hi = b >> 4;
                let lo = b & 0xf;
                let hc = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let lc = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                if pos + 3 < hex.len() {
                    hex[pos] = hc; hex[pos+1] = lc; hex[pos+2] = b' '; pos += 3;
                }
            }
        }
        let s = core::str::from_utf8(&hex[..pos]).unwrap_or("");
        info!("  Instruction bytes at RIP {:#x} (HPA {:#x}): {}", rip, rip_hpa, s);
    } else {
        warn!("  Cannot read instruction bytes at RIP {:#x}: not mapped in EPT", rip);
    }
    drop(zone_guard);
}

fn handle_exception(arch_cpu: &mut ArchCpu, exit_info: &VmxExitInfo) -> HvResult {
    let int_info = VmxInterruptInfo::new()?;

    // Check if the guest has set up its IDT yet.
    // Once the guest IDT is valid, clear the exception bitmap so exceptions
    // are delivered directly to the guest (QEMU reference: exception_bitmap = 0
    // unconditionally). Keeping it 0xFFFFFFFF for a mature guest OS causes page
    // faults and other exceptions to be intercepted, and re-injection can lose
    // the fault address (CR2 may be overwritten during VMM processing).
    let idtr_base = VmcsGuestNW::IDTR_BASE.read().unwrap_or(0);
    if idtr_base != 0 {
        let prev_bm = VmcsControl32::EXCEPTION_BITMAP.read().unwrap_or(0);
        if prev_bm != 0 {
            VmcsControl32::EXCEPTION_BITMAP.write(0).ok();
            info!("[EXCEPTION] Guest IDT detected (IDTR base={:#x}), cleared exception_bitmap (was {:#x})",
                  idtr_base, prev_bm);
        }
    }

    // Exception names
    let exception_names = [
        "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM",
        "#DF", "CSO", "#TS", "#NP", "#SS", "#GP", "#PF", "RES",
        "#MF", "#AC", "#MC", "#XM", "#VE", "RES", "RES", "RES",
        "RES", "RES", "RES", "RES", "RES", "RES", "RES", "RES",
    ];

    let vector = int_info.vector as usize;
    let name = exception_names.get(vector).unwrap_or(&"???");
    let rip = exit_info.guest_rip;

    info!("--- Guest exception: {} (vector {}) at RIP={:#x} ---", name, vector, rip);
    info!("  Interrupt info: {:#x?}", int_info);

    match vector {
        14 => {
            // #PF - Page Fault: walk page tables and dump fault info
            let fault_vaddr = VmcsReadOnlyNW::GUEST_LINEAR_ADDR.read().unwrap_or(0);
            let error_code = VmcsReadOnly32::VMEXIT_INTERRUPTION_ERR_CODE.read().unwrap_or(0);
            let cr3 = VmcsGuestNW::CR3.read().unwrap_or(0);

            // Decode #PF error code
            let pf_p = error_code & 0x1;        // bit 0: protection violation (vs not-present)
            let pf_w = (error_code >> 1) & 0x1; // bit 1: write
            let pf_u = (error_code >> 2) & 0x1; // bit 2: user mode
            let pf_rsvd = (error_code >> 3) & 0x1; // bit 3: reserved bit violation
            let pf_if = (error_code >> 4) & 0x1;   // bit 4: instruction fetch

            info!("  #PF fault_vaddr={:#x}, error_code={:#x} (P={}, W={}, U={}, RSVD={}, IF={})",
                  fault_vaddr, error_code, pf_p, pf_w, pf_u, pf_rsvd, pf_if);
            info!("  RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
                  arch_cpu.regs().rax, arch_cpu.regs().rbx, arch_cpu.regs().rcx, arch_cpu.regs().rdx);
            info!("  RSI={:#x}, RDI={:#x}, RBP={:#x}, RSP={:#x}",
                  arch_cpu.regs().rsi, arch_cpu.regs().rdi, arch_cpu.regs().rbp,
                  VmcsGuestNW::RSP.read().unwrap_or(0));
            info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}, EFER={:#x}",
                  VmcsGuestNW::CR0.read().unwrap_or(0), cr3,
                  VmcsGuestNW::CR4.read().unwrap_or(0),
                  VmcsGuest64::IA32_EFER.read().unwrap_or(0));
            info!("  GS_BASE={:#x}, FS_BASE={:#x}",
                  VmcsGuestNW::GS_BASE.read().unwrap_or(0),
                  VmcsGuestNW::FS_BASE.read().unwrap_or(0));
            info!("  RFLAGS={:#x}",
                  VmcsGuestNW::RFLAGS.read().unwrap_or(0));
            info!("  GDTR base={:#x}, IDTR base={:#x}",
                  VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
                  VmcsGuestNW::IDTR_BASE.read().unwrap_or(0));

            // Walk guest page tables at fault address
            walk_guest_page_table(fault_vaddr, cr3);

            // Also walk at the RIP to see where code is
            if fault_vaddr != rip {
                info!("  (Also walking page table for RIP={:#x})", rip);
                walk_guest_page_table(rip, cr3);
            }

            // Dump instruction bytes at the fault RIP
            dump_instruction_bytes(rip, 16);

            // Set CR2 to the faulting linear address before re-injecting #PF.
            // Per Intel SDM Vol 3C 26.6.1.1, when VM-entry injects a page fault,
            // the page-fault linear address is taken from CR2.  If CR2 was
            // overwritten during VMM processing (e.g. by a host page fault during
            // guest page-table walk), the guest #PF handler sees a bogus address.
            if fault_vaddr != 0 {
                unsafe { core::arch::asm!("mov cr2, {}", in(reg) fault_vaddr) };
            }

            // Re-inject #PF to guest (guest handles it if IDT is set up)
            info!("  => Re-injecting #PF to guest (vector 14, error_code={:#x})", error_code);
            Vmcs::inject_interrupt(14, Some(error_code))?;
        }

        8 => {
            // #DF - Double Fault: read IDT-vectoring info for the original cause
            let idt_vectoring = VmcsReadOnly32::IDT_VECTORING_INFO.read().unwrap_or(0);
            let idt_err = VmcsReadOnly32::IDT_VECTORING_ERR_CODE.read().unwrap_or(0);
            let orig_vector = idt_vectoring & 0xff;
            let orig_type = (idt_vectoring >> 8) & 0x7;
            info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}",
                  VmcsGuestNW::CR0.read().unwrap_or(0),
                  VmcsGuestNW::CR3.read().unwrap_or(0),
                  VmcsGuestNW::CR4.read().unwrap_or(0));
            info!("  GDTR base={:#x}, IDTR base={:#x}",
                  VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
                  VmcsGuestNW::IDTR_BASE.read().unwrap_or(0));
            info!("  IDT-vectoring info={:#x} (orig_vector={}, orig_type={})",
                  idt_vectoring, orig_vector, orig_type);
            if idt_err != 0 {
                info!("  IDT-vectoring error_code={:#x}", idt_err);
            }

            let cr3 = VmcsGuestNW::CR3.read().unwrap_or(0);
            info!("  (Walking page table for RIP={:#x})", rip);
            walk_guest_page_table(rip, cr3);

            info!("  => Re-injecting #DF to guest (will cause triple fault if no IDT)");

            // Shared output: print the last few important lines
            info!("  Registers: RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
                  arch_cpu.regs().rax, arch_cpu.regs().rbx,
                  arch_cpu.regs().rcx, arch_cpu.regs().rdx);
            info!("  RSI={:#x}, RDI={:#x}, RBP={:#x}",
                  arch_cpu.regs().rsi, arch_cpu.regs().rdi, arch_cpu.regs().rbp);

            // Re-inject #DF
            Vmcs::inject_interrupt(8, Some(0))?;
        }

        6 => {
            // #UD - Undefined Opcode: dump instruction bytes
            info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}",
                  VmcsGuestNW::CR0.read().unwrap_or(0),
                  VmcsGuestNW::CR3.read().unwrap_or(0),
                  VmcsGuestNW::CR4.read().unwrap_or(0));
            info!("  GDTR base={:#x}, IDTR base={:#x}",
                  VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
                  VmcsGuestNW::IDTR_BASE.read().unwrap_or(0));

            // Dump instruction bytes - crucial for understanding what instruction is undefined
            dump_instruction_bytes(rip, 16);

            info!("  => Re-injecting #UD to guest");
            Vmcs::inject_interrupt(6, None)?;
        }

        _ => {
            // Generic handling for other exceptions
            info!("  RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
                  arch_cpu.regs().rax, arch_cpu.regs().rbx,
                  arch_cpu.regs().rcx, arch_cpu.regs().rdx);
            info!("  RSI={:#x}, RDI={:#x}, RBP={:#x}",
                  arch_cpu.regs().rsi, arch_cpu.regs().rdi, arch_cpu.regs().rbp);
            info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}",
                  VmcsGuestNW::CR0.read().unwrap_or(0),
                  VmcsGuestNW::CR3.read().unwrap_or(0),
                  VmcsGuestNW::CR4.read().unwrap_or(0));
            info!("  GDTR base={:#x}, IDTR base={:#x}",
                  VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
                  VmcsGuestNW::IDTR_BASE.read().unwrap_or(0));

            // Dump instruction bytes for unknown exceptions
            dump_instruction_bytes(rip, 8);

            info!("  => Re-injecting exception {} to guest", name);
            Vmcs::inject_interrupt(int_info.vector, None)?;
        }
    }

    Ok(())
}

pub fn handle_vmexit(arch_cpu: &mut ArchCpu) -> HvResult {
    let exit_info = VmxExitInfo::new()?;
    debug!("VM exit: {:#x?}", exit_info);

    if exit_info.entry_failure {
        // Get VM instruction error for more details
        let vm_instr_error = Vmcs::instruction_error().unwrap_or_else(|_| VmxInstructionError::from(0xFF));

        // Read all guest state for debugging
        let cr0 = VmcsGuestNW::CR0.read().unwrap_or(0);
        let cr3 = VmcsGuestNW::CR3.read().unwrap_or(0);
        let cr4 = VmcsGuestNW::CR4.read().unwrap_or(0);
        let cs_ar = VmcsGuest32::CS_ACCESS_RIGHTS.read().unwrap_or(0);
        let ss_ar = VmcsGuest32::SS_ACCESS_RIGHTS.read().unwrap_or(0);
        let tr_ar = VmcsGuest32::TR_ACCESS_RIGHTS.read().unwrap_or(0);
        let tr_limit = VmcsGuest32::TR_LIMIT.read().unwrap_or(0);
        let gdtr_base = VmcsGuestNW::GDTR_BASE.read().unwrap_or(0);
        let idtr_base = VmcsGuestNW::IDTR_BASE.read().unwrap_or(0);

        error!("VM entry failed!");
        error!("  VM-instruction error: {:?} ({})", vm_instr_error, vm_instr_error.as_str());
        error!("  Guest state:");
        error!("    CR0={:#x}, CR3={:#x}, CR4={:#x}", cr0, cr3, cr4);
        error!("    CS_AR={:#x}, SS_AR={:#x}, TR_AR={:#x}, TR_LIMIT={:#x}", cs_ar, ss_ar, tr_ar, tr_limit);
        error!("    GDTR_BASE={:#x}, IDTR_BASE={:#x}", gdtr_base, idtr_base);

        panic!("VM entry failed: {:#x?}", exit_info);
    }

    let res = match exit_info.exit_reason {
        VmxExitReason::EXCEPTION_NMI => handle_exception(arch_cpu, &exit_info),
        VmxExitReason::EXTERNAL_INTERRUPT => handle_external_interrupt(),
        VmxExitReason::TRIPLE_FAULT => handle_triple_fault(arch_cpu, &exit_info),
        VmxExitReason::INTERRUPT_WINDOW => Vmcs::set_interrupt_window(false),
        VmxExitReason::CPUID => handle_cpuid(arch_cpu),
        VmxExitReason::HLT => {
            arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_HLT)?;
            Ok(())
        }
        VmxExitReason::VMCALL => handle_hypercall(arch_cpu),
        VmxExitReason::CR_ACCESS => handle_cr_access(arch_cpu),
        VmxExitReason::IO_INSTRUCTION => handle_io_instruction(arch_cpu, &exit_info),
        VmxExitReason::MSR_READ => handle_msr_read(arch_cpu),
        VmxExitReason::MSR_WRITE => handle_msr_write(arch_cpu),
        VmxExitReason::EPT_VIOLATION => handle_s2pt_violation(arch_cpu, &exit_info),
        _ => panic!(
            "Unhandled VM-Exit reason {:?}:\n{:#x?}",
            exit_info.exit_reason, arch_cpu
        ),
    };

    if res.is_err() {
        panic!(
            "Failed to handle VM-exit {:?}:\n{:#x?}\n{:?}",
            exit_info.exit_reason,
            arch_cpu,
            res.err()
        );
    }

    Ok(())
}
