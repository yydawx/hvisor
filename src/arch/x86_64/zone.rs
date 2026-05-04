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
    device::{
        irqchip::pic::ioapic::ioapic_reroute_from_cpus,
        virtio_trampoline::mmio_virtio_handler,
    },
    error::HvResult,
    memory::{GuestPhysAddr, HostPhysAddr, MemFlags, MemoryRegion, MemorySet, MMIOAccess, mmio_perform_access},
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

        // For non-root zones: re-route critical physical interrupts (e.g. UART)
        // away from CPUs that will run the new zone, so they stay in the root
        // zone and zone0 doesn't lose interactive console.
        if zone_id != 0 {
            ioapic_reroute_from_cpus(&self.cpu_set);
        }

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

        // Copy ACPI tables for all zones (including Multiboot2 mode).
        // Zone1 uses dedicated RSDP region (ID 1) and ACPI region (ID 3)
        // at non-conflicting GPAs (0xe0000 and 0x1ff00000 respectively).
        acpi::copy_to_guest_memory_region(&config, &self.cpu_set);

        // Map PCI ECAM region into guest EPT so the guest can access PCI config space.
        // The MCFG table tells the guest ECAM is at HPA 0xb0000000, which becomes
        // GPA 0xb0000000 when copied into guest ACPI tables. Without this mapping,
        // any PCI config access causes an EPT violation.
        if self.id == 0 {
            // Zone0: full ECAM identity-map
            let ecam_base = 0xb000_0000usize;
            let ecam_size = 0x20_0000usize;
            self.gpm.insert(MemoryRegion::new_with_offset_mapper(
                ecam_base as GuestPhysAddr,
                ecam_base as HostPhysAddr,
                ecam_size,
                MemFlags::READ | MemFlags::WRITE,
            ));
        } else {
            // Non-root zone: identity-map ECAM except for the page containing
            // the virtio-blk device (01:00.0). That page gets an MMIO handler
            // that returns 0xffffffff for the vendor-ID read, hiding the device
            // so the guest never tries to access its BAR and corrupt IOMMU state.
            let ecam_base = 0xb000_0000usize;
            let virtio_blk_ecam_gpa = ecam_base + 0x10_0000; // bus 1, dev 0, func 0
            let ecam_page = 0x1000usize;

            // ECAM before virtio-blk page: 0xb0000000..0xb0100000
            if virtio_blk_ecam_gpa > ecam_base {
                self.gpm.insert(MemoryRegion::new_with_offset_mapper(
                    ecam_base as GuestPhysAddr,
                    ecam_base as HostPhysAddr,
                    virtio_blk_ecam_gpa - ecam_base,
                    MemFlags::READ | MemFlags::WRITE,
                ));
            }
            // Virtio-blk ECAM page: MMIO-handler that hides the device
            self.mmio_region_register(
                virtio_blk_ecam_gpa,
                ecam_page,
                ecam_virtio_blk_hide_handler,
                virtio_blk_ecam_gpa,
            );
            // ECAM after virtio-blk page: 0xb0101000..0xb0200000
            let after_gpa = virtio_blk_ecam_gpa + ecam_page;
            let ecam_end = ecam_base + 0x20_0000usize;
            if after_gpa < ecam_end {
                self.gpm.insert(MemoryRegion::new_with_offset_mapper(
                    after_gpa as GuestPhysAddr,
                    after_gpa as HostPhysAddr,
                    ecam_end - after_gpa,
                    MemFlags::READ | MemFlags::WRITE,
                ));
            }
        }

        // Map PCI 32-bit MMIO window so the guest can access PCI device BARs.
        let pci_mmio_base = 0xC000_0000usize;
        let pci_mmio_size = 0x3EB0_0000usize;  // up to 0xFEB00000
        self.gpm.insert(MemoryRegion::new_with_offset_mapper(
            pci_mmio_base as GuestPhysAddr,
            pci_mmio_base as HostPhysAddr,
            pci_mmio_size,
            MemFlags::READ | MemFlags::WRITE,
        ));

        // Continue PCI MMIO after the virtio MMIO hole
        let pci_mmio2_base = 0xFEB0_1000usize;
        let pci_mmio2_size = 0xFF000usize;  // ~1MB, up to IOAPIC at 0xFEC00000
        self.gpm.insert(MemoryRegion::new_with_offset_mapper(
            pci_mmio2_base as GuestPhysAddr,
            pci_mmio2_base as HostPhysAddr,
            pci_mmio2_size,
            MemFlags::READ | MemFlags::WRITE,
        ));

        // Map 64-bit PCI BAR window for non-root zones (zone0 maps it below too,
        // but via the RAM regions which cover all of HPA).
        let pci_bar64_base = 0x8_0000_0000usize;
        let pci_bar64_size = 0x1000_0000usize;
        self.gpm.insert(MemoryRegion::new_with_offset_mapper(
            pci_bar64_base as GuestPhysAddr,
            pci_bar64_base as HostPhysAddr,
            pci_bar64_size,
            MemFlags::READ | MemFlags::WRITE,
        ));

        // Map DMA memory region for non-root zones: cover the guest's I/O memory
        // allocator low range (0x20000000..0xB0000000, i.e. up to ECAM) using
        // HPA 0x1_0000_0000 (4GB, reserved for zone1 by zone0).
        if self.id != 0 {
            let dma_gpa_base = 0x2000_0000usize;
            let dma_hpa_base = 0x1_0000_0000usize;
            let dma_size = 0x9000_0000usize;  // 2.25GB, up to ECAM at 0xB0000000
            self.gpm.insert(MemoryRegion::new_with_offset_mapper(
                dma_gpa_base as GuestPhysAddr,
                dma_hpa_base as HostPhysAddr,
                dma_size,
                MemFlags::READ | MemFlags::WRITE,
            ));
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

/// ECAM MMIO handler that hides the virtio-blk device (01:00.0) from non-root
/// zones.  Returns 0xffffffff for the vendor-ID read at offset 0 so the guest
/// thinks no device is present.  All other accesses are passed through to the
/// hardware.
///
/// Without this filter, a non-root zone discovers zone0's virtio-blk, sets up
/// DMA through it, and corrupts the IOMMU DMA-remapping state (the IOMMU
/// context entry points to zone0's EPT, not the non-root zone's).
fn ecam_virtio_blk_hide_handler(mmio: &mut MMIOAccess, ecam_hpa: usize) -> HvResult {
    // Offset 0 in the 4 KiB ECAM page: vendor-ID (bits 0..15) + device-ID (bits 16..31)
    if !mmio.is_write && mmio.address == 0 {
        // Return invalid vendor-ID so the guest thinks the device doesn't exist
        mmio.value = 0xffff_ffff;
        Ok(())
    } else if mmio.is_write && mmio.address == 0 {
        // Silently discard writes to vendor-ID (prevent hot-adding the device)
        Ok(())
    } else {
        // Pass through all other config-space accesses to the real hardware
        mmio_perform_access(ecam_hpa, mmio);
        Ok(())
    }
}
