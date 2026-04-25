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
    arch::{acpi, boot, msr::set_msr_bitmap, pio, pio::set_pio_bitmap, Stage2PageTable},
    config::*,
    cpu_data::get_cpu_data,
    device::virtio_trampoline::mmio_virtio_handler,
    error::HvResult,
    memory::{GuestPhysAddr, HostPhysAddr, MemFlags, MemoryRegion, MemorySet},
    platform::MEM_TYPE_RESERVED,
    zone::Zone,
};
use alloc::vec::Vec;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HvArchZoneConfig {
    /// base address of ioapic mmio registers, usually 0xfec00000
    pub ioapic_base: usize,
    /// size of ioapic mmio registers, usually 0x1000
    pub ioapic_size: usize,
    /// start gpa of vmlinux.bin, usually 0x100000
    pub kernel_entry_gpa: usize,
    /// gpa of linux boot command line
    pub cmdline_load_gpa: usize,
    /// start gpa of setup.bin, address length no bigger than 16 bits
    pub setup_load_gpa: usize,
    /// If you want to use initrd, set initrd_load_gpa and initrd_size.
    /// Otherwise, leave them as zero. The memory region type of
    /// initrd should be set to MEM_TYPE_RESERVED.
    /// initrd_load_gpa is the start gpa of initrd
    pub initrd_load_gpa: usize,
    /// size of initrd
    pub initrd_size: usize,
    /// RSDP table will be copied to the memory region with this id.
    /// The start gpa of this memory region should 0xe_0000
    /// and the size should be 0x2_0000. Set its type to MEM_TYPE_RAM.
    pub rsdp_memory_region_id: usize,
    /// Other ACPI tables will be copied to the memory region with this id.
    /// no restriction on start gpa and size, but its type should be MEM_TYPE_RAM as well.
    /// Usually, the DSDT table is large, so the size of this region should be large enough.
    pub acpi_memory_region_id: usize,
    pub uefi_memory_region_id: usize,
    /// If you want to use a graphical console, set screen_base to a preferred gpa
    /// as the start of the framebuffer. Otherwise, leave it as zero.
    /// No need to add a memory region for the framebuffer,
    /// Hvisor will do the job. **IMPORTANT: screen_base should be no longer than 32 bits.**
    pub screen_base: usize,
}

impl Zone {
    pub fn pt_init(&mut self, mem_regions: &[HvConfigMemoryRegion]) -> HvResult {
        for mem_region in mem_regions.iter() {
            let mut flags = MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE;
            if mem_region.mem_type == MEM_TYPE_IO {
                flags |= MemFlags::IO;
            }
            match mem_region.mem_type {
                MEM_TYPE_RAM | MEM_TYPE_IO | MEM_TYPE_RESERVED => {
                    self.gpm.insert(MemoryRegion::new_with_offset_mapper(
                        mem_region.virtual_start as GuestPhysAddr,
                        mem_region.physical_start as HostPhysAddr,
                        mem_region.size as _,
                        flags,
                    ));
                }
                MEM_TYPE_VIRTIO => {
                    self.mmio_region_register(
                        mem_region.physical_start as _,
                        mem_region.size as _,
                        mmio_virtio_handler,
                        mem_region.physical_start as _,
                    );
                }
                _ => {
                    panic!("Unsupported memory type: {}", mem_region.mem_type)
                }
            }
        }

        // info!("VM stage 2 memory set: {:#x?}", self.gpm);
        Ok(())
    }

    pub fn irq_bitmap_init(&mut self, irqs_bitmap: &[u32]) {}

    /// called after cpu_set is initialized
    pub fn arch_zone_pre_configuration(&mut self, config: &HvZoneConfig) -> HvResult {
        let zone_id = config.zone_id as usize;

        // Check if this is zone1 (Multiboot2) or zone0 (Linux)
        if zone_id != 0 && config.multiboot_enabled != 0 {
            // Zone1 with Multiboot2 - use Multiboot2 boot mode
            info!("[ZONE{}] Using Multiboot2 boot mode", zone_id);
            info!("[ZONE{}] multiboot_enabled={}, config.multiboot_info_paddr={:#x}",
                  zone_id, config.multiboot_enabled, config.multiboot_info_paddr);

            // Use kernel's existing GDT at GPA 0x80014f0
            // The kernel's GDT has:
            // - Selector 0x08: 64-bit code segment
            // - Selector 0x10: Data segment
            // - Selector 0x18: 32-bit code segment
            //
            // We need a TSS for VMX. Put it at GPA 0x8048000 (below stack at 0x804a000)
            // DO NOT use 0x8009000 - that's kernel boot code!
            let tss_gpa = 0x8048000usize;
            if let Ok((tss_hpa, _, _)) = unsafe { self.gpm.page_table_query(tss_gpa) } {
                let tss_ptr = tss_hpa as *mut u8;
                unsafe {
                    // Zero out 104 bytes (32-bit TSS size)
                    for i in 0..104 {
                        core::ptr::write_volatile(tss_ptr.add(i), 0);
                    }
                }
                info!("[ZONE{}] TSS written to GPA {:#x} (HPA {:#x})", zone_id, tss_gpa, tss_hpa);
            } else {
                warn!("[ZONE{}] Failed to write TSS: GPA {:#x} not mapped", zone_id, tss_gpa);
            }

            // Add TSS descriptor to kernel's GDT at entry 4 (selector 0x20)
            // TSS descriptor: Base=0x8048000, Limit=0x67, Type=0x89 (32-bit available TSS)
            let tss_descriptor: u64 = 0x0080890480000067;
            let gdt_entry4_gpa = 0x80014f0 + 4 * 8;  // Entry 4 at offset 32
            if let Ok((gdt_hpa, _, _)) = unsafe { self.gpm.page_table_query(gdt_entry4_gpa) } {
                let gdt_ptr = gdt_hpa as *mut u64;
                unsafe {
                    core::ptr::write_volatile(gdt_ptr, tss_descriptor);
                }
                info!("[ZONE{}] TSS descriptor written to GDT entry 4 at GPA {:#x}", zone_id, gdt_entry4_gpa);
            }

            self.cpu_set.iter().for_each(|cpuid| {
                let cpu_data = get_cpu_data(cpuid);
                if cpuid == self.cpu_set.first_cpu().unwrap() {
                    cpu_data.arch_cpu.set_multiboot_mode(true);
                    cpu_data.arch_cpu.set_multiboot_boot_regs(
                        config.multiboot_info_paddr as _,
                    );
                    info!("[ZONE{}] Multiboot2: EAX=0x36D76289, EBX=0x{:x}",
                        zone_id, config.multiboot_info_paddr);
                }
            });
        } else {
            self.cpu_set.iter().for_each(|cpuid| {
                let cpu_data = get_cpu_data(cpuid);
                if cpuid == self.cpu_set.first_cpu().unwrap() {
                    cpu_data.arch_cpu.set_multiboot_mode(false);
                    cpu_data.arch_cpu.set_boot_cpu_vm_launch_regs(
                        config.arch_config.kernel_entry_gpa as _,
                        config.arch_config.setup_load_gpa as _,
                    );
                }
            });
        }

        set_msr_bitmap(config.zone_id as _);
        set_pio_bitmap(config.zone_id as _);

        Ok(())
    }

    pub fn arch_zone_post_configuration(&mut self, config: &HvZoneConfig) -> HvResult {
        /*let mut msix_bar_regions: Vec<BarRegion> = Vec::new();
        for region in self.pciroot.bar_regions.iter_mut() {
            // check whether this bar is msi-x table
            // if true, use msi-x table handler instead
            if region.bar_type != BarType::IO {
                if let Some(bdf) = acpi::is_msix_bar(region.start) {
                    info!("msi-x bar! hpa: {:x} bdf: {:x}", region.start, bdf);
                    msix_bar_regions.push(region.clone());

                    continue;
                }
            }
        }
        for region in msix_bar_regions.iter() {
            self.mmio_region_register(
                region.start,
                region.size,
                crate::memory::mmio_generic_handler,
                region.start,
            );
        }

        if self.id == 0 {
            self.pci_bars_register(&config.pci_config);
        }*/

        boot::BootParams::fill(&config, &mut self.gpm);

        // Skip ACPI table copy for Multiboot mode - the kernel will handle hardware discovery
        // Also, config.acpi_memory_region_id = 0 would overwrite kernel code at GPA 0x8000000
        if config.multiboot_enabled == 0 {
            acpi::copy_to_guest_memory_region(&config, &self.cpu_set);
        } else {
            info!("[ZONE{}] Skipping ACPI table copy for Multiboot mode", config.zone_id);
        }

        Ok(())
    }
}

/*impl BarRegion {
    pub fn arch_set_bar_region_start(&mut self, cpu_base: usize, pci_base: usize) {
        self.start = cpu_base + self.start - pci_base;
        if self.bar_type != BarType::IO {
            self.start = crate::memory::addr::align_down(self.start);
        }
    }

    pub fn arch_insert_bar_region(&self, gpm: &mut MemorySet<Stage2PageTable>, zone_id: usize) {
        if self.bar_type != BarType::IO {
            gpm.insert(MemoryRegion::new_with_offset_mapper(
                self.start as GuestPhysAddr,
                self.start,
                self.size,
                MemFlags::READ | MemFlags::WRITE | MemFlags::IO,
            ))
            .ok();
        } else {
            pio::get_pio_bitmap(zone_id).set_range_intercept(
                (self.start as u16)..((self.start + self.size) as u16),
                false,
            );
        }
    }
}*/
