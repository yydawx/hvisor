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
        vmx::{VmxCrAccessInfo, VmxExitInfo, VmxExitReason, VmxInstructionError, VmxInterruptInfo, VmxIoExitInfo},
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
    memory::{mmio_handle_access, MMIOAccess, MemFlags},
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
        IdtVector::APIC_SPURIOUS_VECTOR | IdtVector::APIC_ERROR_VECTOR => {}
        _ => {
            if vector >= 0x20 && this_cpu_data().arch_cpu.power_on {
                inject_vector(this_cpu_id(), vector, None, false);
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

    if let Ok(msr) = Msr::try_from(rcx) {
        let res: HvResult<u64> = if msr == IA32_APIC_BASE {
            let mut apic_base = unsafe { IA32_APIC_BASE.read() };
            // info!("APIC BASE: {:x}", apic_base);
            apic_base |= 1 << 11 | 1 << 10; // enable xAPIC and x2APIC
            Ok(apic_base)
        } else if VirtLocalApic::msr_range().contains(&rcx) {
            arch_cpu.virt_lapic.rdmsr(msr)
        } else if msr == IA32_GS_BASE {
            // Read Guest GS_BASE from VMCS
            match VmcsGuestNW::GS_BASE.read() {
                Ok(v) => Ok(v as u64),
                Err(_) => hv_result_err!(EIO),
            }
        } else if msr == IA32_FS_BASE {
            // Read Guest FS_BASE from VMCS
            match VmcsGuestNW::FS_BASE.read() {
                Ok(v) => Ok(v as u64),
                Err(_) => hv_result_err!(EIO),
            }
        } else {
            hv_result_err!(ENOSYS)
        };

        if let Ok(value) = res {
            debug!("VM exit: RDMSR({:#x}) -> {:#x}", rcx, value);
            arch_cpu.regs_mut().rax = value & 0xffff_ffff;
            arch_cpu.regs_mut().rdx = value >> 32;
        } else {
            warn!("Failed to handle RDMSR({:#x}): {:?}", rcx, res);
        }
    } else {
        // warn!("Unrecognized RDMSR({:#x})", rcx);
    }

    arch_cpu.advance_guest_rip(VM_EXIT_INSTR_LEN_RDMSR)?;
    Ok(())
}

fn handle_msr_write(arch_cpu: &mut ArchCpu) -> HvResult {
    let rcx = arch_cpu.regs().rcx as u32;
    let msr = Msr::try_from(rcx).unwrap();
    let value = (arch_cpu.regs().rax & 0xffff_ffff) | (arch_cpu.regs().rdx << 32);
    debug!("VM exit: WRMSR({:#x}) <- {:#x}", rcx, value);

    let res: HvResult<()> = if msr == IA32_APIC_BASE {
        Ok(()) // ignore
    } else if VirtLocalApic::msr_range().contains(&rcx) || msr == IA32_TSC_DEADLINE {
        arch_cpu.virt_lapic.wrmsr(msr, value)
    } else if msr == IA32_GS_BASE {
        // Write Guest GS_BASE to VMCS
        info!("[MSR] WRMSR GS_BASE <- {:#x}", value);
        match VmcsGuestNW::GS_BASE.write(value as usize) {
            Ok(()) => {
                // Verify write
                let read_back = VmcsGuestNW::GS_BASE.read().unwrap_or(0);
                info!("[MSR] GS_BASE written, read back: {:#x}", read_back);
                Ok(())
            },
            Err(_) => hv_result_err!(EIO),
        }
    } else if msr == IA32_FS_BASE {
        // Write Guest FS_BASE to VMCS
        info!("[MSR] WRMSR FS_BASE <- {:#x}", value);
        match VmcsGuestNW::FS_BASE.write(value as usize) {
            Ok(()) => Ok(()),
            Err(_) => hv_result_err!(EIO),
        }
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

    // Debug: print detailed EPT violation info
    info!("EPT violation at GPA {:#x}", fault_info.fault_guest_paddr);
    info!("  RIP={:#x}, RSP={:#x}", exit_info.guest_rip, VmcsGuestNW::RSP.read().unwrap_or(0));
    info!("  Access: read={}, write={}, exec={}",
        fault_info.access_flags.contains(MemFlags::READ),
        fault_info.access_flags.contains(MemFlags::WRITE),
        fault_info.access_flags.contains(MemFlags::EXECUTE));

    // Print VM-exit instruction length
    let instr_len = VmcsReadOnly32::VMEXIT_INSTRUCTION_LEN.read().unwrap_or(0);
    info!("  VM-exit instruction length: {}", instr_len);

    // Check if this is a PUSH instruction issue
    let gla = VmcsReadOnlyNW::GUEST_LINEAR_ADDR.read().unwrap_or(0);
    let rsp = VmcsGuestNW::RSP.read().unwrap_or(0);
    let ss_base = VmcsGuestNW::SS_BASE.read().unwrap_or(0);
    info!("  Stack analysis: RSP={:#x}, SS.base={:#x}, expected write addr={:#x}",
          rsp, ss_base, ss_base.wrapping_add(rsp).wrapping_sub(4));
    info!("  Actual GLA={:#x}, difference={:#x}", gla, gla.abs_diff(ss_base.wrapping_add(rsp).wrapping_sub(4)));

    // Print all guest registers for debugging
    info!("  Guest GPRs: RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
          arch_cpu.regs().rax, arch_cpu.regs().rbx, arch_cpu.regs().rcx, arch_cpu.regs().rdx);
    info!("  Guest GPRs: RSI={:#x}, RDI={:#x}, RBP={:#x}, R8={:#x}",
          arch_cpu.regs().rsi, arch_cpu.regs().rdi, arch_cpu.regs().rbp, arch_cpu.regs().r8);

    // Print all segment bases and selectors
    info!("  Segment details:");
    info!("    CS: sel={:#x}, base={:#x}, limit={:#x}, ar={:#x}",
          VmcsGuest16::CS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::CS_BASE.read().unwrap_or(0),
          VmcsGuest32::CS_LIMIT.read().unwrap_or(0),
          VmcsGuest32::CS_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    DS: sel={:#x}, base={:#x}, ar={:#x}",
          VmcsGuest16::DS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::DS_BASE.read().unwrap_or(0),
          VmcsGuest32::DS_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    ES: sel={:#x}, base={:#x}, ar={:#x}",
          VmcsGuest16::ES_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::ES_BASE.read().unwrap_or(0),
          VmcsGuest32::ES_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    SS: sel={:#x}, base={:#x}, limit={:#x}, ar={:#x}",
          VmcsGuest16::SS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::SS_BASE.read().unwrap_or(0),
          VmcsGuest32::SS_LIMIT.read().unwrap_or(0),
          VmcsGuest32::SS_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    FS: sel={:#x}, base={:#x}, ar={:#x}",
          VmcsGuest16::FS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::FS_BASE.read().unwrap_or(0),
          VmcsGuest32::FS_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    GS: sel={:#x}, base={:#x}, ar={:#x}",
          VmcsGuest16::GS_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::GS_BASE.read().unwrap_or(0),
          VmcsGuest32::GS_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    TR: sel={:#x}, base={:#x}, limit={:#x}, ar={:#x}",
          VmcsGuest16::TR_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::TR_BASE.read().unwrap_or(0),
          VmcsGuest32::TR_LIMIT.read().unwrap_or(0),
          VmcsGuest32::TR_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    LDTR: sel={:#x}, base={:#x}, ar={:#x}",
          VmcsGuest16::LDTR_SELECTOR.read().unwrap_or(0),
          VmcsGuestNW::LDTR_BASE.read().unwrap_or(0),
          VmcsGuest32::LDTR_ACCESS_RIGHTS.read().unwrap_or(0));
    info!("    GDTR: base={:#x}, limit={:#x}",
          VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
          VmcsGuest32::GDTR_LIMIT.read().unwrap_or(0));
    info!("    IDTR: base={:#x}, limit={:#x}",
          VmcsGuestNW::IDTR_BASE.read().unwrap_or(0),
          VmcsGuest32::IDTR_LIMIT.read().unwrap_or(0));

    // Exit qualification provides more info about the violation
    let qualification = VmcsReadOnlyNW::EXIT_QUALIFICATION.read().unwrap_or(0);
    info!("  Exit qualification={:#x} (bit4={})", qualification, (qualification >> 4) & 1);

    // Read guest linear address (if available)
    let gla = VmcsReadOnlyNW::GUEST_LINEAR_ADDR.read().unwrap_or(0);
    info!("  Guest linear address={:#x}", gla);

    // For debugging Multiboot2 boot issues, check if RIP is at entry point
    let rip = exit_info.guest_rip;

    // Print instruction bytes at RIP for debugging
    info!("  Instruction bytes at RIP:");
    let binding = this_zone();
    let zone = binding.read();
    if let Ok((rip_hpa, _, _)) = unsafe { zone.gpm.page_table_query(rip) } {
        let rip_ptr = rip_hpa as *const u8;
        let mut bytes = [0u8; 16];
        unsafe {
            for i in 0..16 {
                bytes[i] = core::ptr::read_volatile(rip_ptr.add(i));
            }
        }
        info!("    RIP {:#x} (HPA {:#x}): {:02x?}", rip, rip_hpa, bytes);
    } else {
        warn!("    Cannot read instruction bytes: RIP {:#x} not mapped in EPT", rip);
    }
    drop(zone); // Release the lock

    if rip >= 0x8000000 && rip < 0x9000000 {
        // Print GDT content for debugging
        let gdtr_base = VmcsGuestNW::GDTR_BASE.read().unwrap_or(0);
        info!("  GDT content at GPA {:#x}:", gdtr_base);
        let zone_guard = this_zone();
        let zone = zone_guard.read();
        for i in 0..6 {
            let gdt_entry_gpa = gdtr_base + i * 8;
            if let Ok((gdt_hpa, _, _)) = unsafe { zone.gpm.page_table_query(gdt_entry_gpa) } {
                let gdt_ptr = gdt_hpa as *const u64;
                let entry = unsafe { core::ptr::read_volatile(gdt_ptr) };
                info!("    GDT[{0}] (sel=0x{0:02x}): {1:#018x}", i * 8, entry);
            }
        }
        drop(zone);
        // This might be zone1 Multiboot boot - print more details
        info!("  Possible Multiboot boot issue, RIP in kernel range");
        info!("  Guest state summary:");
        info!("    CR0={:#x}, CR3={:#x}, CR4={:#x}, EFER={:#x}",
            VmcsGuestNW::CR0.read().unwrap_or(0),
            VmcsGuestNW::CR3.read().unwrap_or(0),
            VmcsGuestNW::CR4.read().unwrap_or(0),
            VmcsGuest64::IA32_EFER.read().unwrap_or(0));
        info!("    CS: sel={:#x}, base={:#x}, ar={:#x}",
            VmcsGuest16::CS_SELECTOR.read().unwrap_or(0),
            VmcsGuestNW::CS_BASE.read().unwrap_or(0),
            VmcsGuest32::CS_ACCESS_RIGHTS.read().unwrap_or(0));
        info!("    GDTR: base={:#x}, limit={:#x}",
            VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
            VmcsGuest32::GDTR_LIMIT.read().unwrap_or(0));
        info!("    IDTR: base={:#x}, limit={:#x}",
            VmcsGuestNW::IDTR_BASE.read().unwrap_or(0),
            VmcsGuest32::IDTR_LIMIT.read().unwrap_or(0));
        info!("    TR: sel={:#x}, base={:#x}",
            VmcsGuest16::TR_SELECTOR.read().unwrap_or(0),
            VmcsGuestNW::TR_BASE.read().unwrap_or(0));
    }

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

fn handle_exception(arch_cpu: &mut ArchCpu, exit_info: &VmxExitInfo) -> HvResult {
    let int_info = VmxInterruptInfo::new()?;

    // Exception names
    let exception_names = [
        "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM",
        "#DF", "CSO", "#TS", "#NP", "#SS", "#GP", "#PF", "RES",
        "#MF", "#AC", "#MC", "#XM", "#VE", "RES", "RES", "RES",
        "RES", "RES", "RES", "RES", "RES", "RES", "RES", "RES",
    ];

    let vector = int_info.vector as usize;
    let name = exception_names.get(vector).unwrap_or(&"???");

    info!("Guest exception: {} (vector {}) at RIP={:#x}", name, vector, exit_info.guest_rip);
    info!("  Interrupt info: {:#x?}", int_info);
    info!("  RAX={:#x}, RBX={:#x}, RCX={:#x}, RDX={:#x}",
          arch_cpu.regs().rax, arch_cpu.regs().rbx, arch_cpu.regs().rcx, arch_cpu.regs().rdx);
    info!("  RSI={:#x}, RDI={:#x}, RBP={:#x}",
          arch_cpu.regs().rsi, arch_cpu.regs().rdi, arch_cpu.regs().rbp);
    info!("  CR0={:#x}, CR3={:#x}, CR4={:#x}",
          VmcsGuestNW::CR0.read().unwrap_or(0),
          VmcsGuestNW::CR3.read().unwrap_or(0),
          VmcsGuestNW::CR4.read().unwrap_or(0));
    info!("  GS_BASE={:#x}, FS_BASE={:#x}",
          VmcsGuestNW::GS_BASE.read().unwrap_or(0),
          VmcsGuestNW::FS_BASE.read().unwrap_or(0));
    info!("  CS={:#x}, DS={:#x}, SS={:#x}",
          VmcsGuest16::CS_SELECTOR.read().unwrap_or(0),
          VmcsGuest16::DS_SELECTOR.read().unwrap_or(0),
          VmcsGuest16::SS_SELECTOR.read().unwrap_or(0));
    info!("  GDTR base={:#x}, IDTR base={:#x}",
          VmcsGuestNW::GDTR_BASE.read().unwrap_or(0),
          VmcsGuestNW::IDTR_BASE.read().unwrap_or(0));

    // For now, halt on any exception
    panic!(
        "Unhandled guest exception {} (vector {}) at RIP={:#x}\n{:#x?}",
        name, vector, exit_info.guest_rip, arch_cpu
    );
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
