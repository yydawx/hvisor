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
        acpi::{get_apic_id, get_cpu_id},
        cpu::this_cpu_id,
        idt, ipi,
        mmio::MMIoDevice,
        zone::HvArchZoneConfig,
    },
    cpu_data::this_zone,
    device::irqchip::pic::inject_vector,
    error::HvResult,
    memory::{GuestPhysAddr, MMIOAccess},
    platform::ROOT_ZONE_IOAPIC_BASE,
    zone::{this_zone_id, Zone},
};
use alloc::{sync::Arc, vec::Vec};
use bit_field::BitField;
use core::{ops::Range, u32};
use spin::{Mutex, Once};
use x2apic::ioapic::IoApic;
use x86_64::instructions::port::Port;

pub mod irqs {
    pub const UART_COM1_IRQ: u8 = 0x4;
}

#[allow(non_snake_case)]
pub mod IoApicReg {
    pub const ID: u32 = 0x00;
    pub const VERSION: u32 = 0x01;
    pub const ARBITRATION: u32 = 0x02;
    pub const TABLE_BASE: u32 = 0x10;
}

const IOAPIC_MAX_REDIRECT_ENTRIES: u64 = 0x17;

lazy_static::lazy_static! {
    static ref IO_APIC: Mutex<IoApic> = {
        unsafe { Mutex::new(IoApic::new(ROOT_ZONE_IOAPIC_BASE as _)) }
    };
}

static VIRT_IOAPIC: Once<VirtIoApic> = Once::new();

#[derive(Default)]
struct VirtIoApicUnlocked {
    cur_reg: u32,
    rte: [u64; (IOAPIC_MAX_REDIRECT_ENTRIES + 1) as usize],
}

pub struct VirtIoApic {
    inner: Vec<Mutex<VirtIoApicUnlocked>>,
}

impl VirtIoApic {
    pub fn new(max_zones: usize) -> Self {
        let mut vs = vec![];
        for _ in 0..max_zones {
            let v = Mutex::new(VirtIoApicUnlocked::default());
            vs.push(v)
        }
        Self { inner: vs }
    }

    fn read(&self, gpa: GuestPhysAddr) -> HvResult<u64> {
        // info!("ioapic read! gpa: {:x}", gpa,);
        let zone_id = this_zone_id();
        let ioapic = self.inner.get(zone_id).unwrap();

        if gpa == 0 {
            return Ok(ioapic.lock().cur_reg as _);
        }
        assert!(gpa == 0x10);

        let inner = ioapic.lock();
        match inner.cur_reg {
            IoApicReg::ID => Ok(0),
            IoApicReg::VERSION => Ok(IOAPIC_MAX_REDIRECT_ENTRIES << 16 | 0x11), // max redirect entries: 0x17, version: 0x11
            IoApicReg::ARBITRATION => Ok(0),
            mut reg => {
                reg -= IoApicReg::TABLE_BASE;
                let index = (reg >> 1) as usize;
                if let Some(entry) = inner.rte.get(index) {
                    if reg % 2 == 0 {
                        Ok((*entry).get_bits(0..=31))
                    } else {
                        Ok((*entry).get_bits(32..=63))
                    }
                } else {
                    Ok(0)
                }
            }
        }
    }

    fn write(&self, gpa: GuestPhysAddr, value: u64, size: usize) -> HvResult {
        /*info!(
            "ioapic write! gpa: {:x}, value: {:x}, size: {:x}",
            gpa, value, size,
        );*/

        let zone_id = this_zone_id();
        let ioapic = self.inner.get(zone_id).unwrap();
        if gpa == 0 {
            ioapic.lock().cur_reg = value as _;
            return Ok(());
        }
        assert!(gpa == 0x10);

        let mut inner = ioapic.lock();
        match inner.cur_reg {
            IoApicReg::ID | IoApicReg::VERSION | IoApicReg::ARBITRATION => {}
            mut reg => {
                reg -= IoApicReg::TABLE_BASE;
                let index = (reg >> 1) as usize;
                if let Some(entry) = inner.rte.get_mut(index) {
                    if reg % 2 == 0 {
                        entry.set_bits(0..=31, value.get_bits(0..=31));
                    } else {
                        entry.set_bits(32..=63, value.get_bits(0..=31));

                        /*if zone_id == 0 {
                            // info!("1 write {:x} entry: {:x?}", index, *entry);
                            // only root zone modify the real I/O APIC
                            // unsafe { configure_gsi_from_raw(index as _, *entry) };
                        }*/
                    }
                    if zone_id == 0 {
                        // only root zone modify the real I/O APIC
                        unsafe { configure_gsi_from_raw(index as _, *entry) };
                    }
                }
            }
        }
        Ok(())
    }

    fn get_irq_cpu(&self, irq: usize, zone_id: usize) -> Option<usize> {
        let ioapic = self.inner.get(zone_id).unwrap();
        if let Some(entry) = ioapic.lock().rte.get(irq) {
            let dest = get_cpu_id(entry.get_bits(56..=63) as usize);
            return Some(dest);
        }
        None
    }

    fn trigger(&self, irq: usize, allow_repeat: bool) -> HvResult {
        let zone_id = this_zone_id();
        let ioapic = self.inner.get(zone_id).unwrap();
        if let Some(entry) = ioapic.lock().rte.get(irq) {
            // TODO: physical & logical mode
            let dest = get_cpu_id(entry.get_bits(56..=63) as usize);
            let masked = entry.get_bit(16);
            let vector = entry.get_bits(0..=7) as u8;
            if !masked && vector >= 0x20 {
                let this_zone_arc = this_zone();
                let zone = this_zone_arc.read();
                // The guest IOAPIC RTE may route to a CPU outside this zone.
                // If so, redirect to the zone's first CPU so the interrupt
                // reaches the correct guest.
                let dest = if zone.cpu_set.bitmap & (1u64 << dest) != 0 {
                    dest
                } else {
                    let fallback = zone.cpu_set.first_cpu().unwrap();
                    trace!(
                        "ioapic: IRQ {} dest CPU {} not in zone {}, using CPU {}",
                        irq, dest, zone_id, fallback
                    );
                    fallback
                };
                drop(zone);
                inject_vector(dest, vector, None, allow_repeat);
            }
        } else {
            warn!(
                "ioapic trigger: IRQ {} out of range (max {}) for zone {}, ignoring",
                irq,
                IOAPIC_MAX_REDIRECT_ENTRIES,
                zone_id
            );
        }
        Ok(())
    }
}

impl Zone {
    pub fn ioapic_mmio_init(&mut self, arch: &HvArchZoneConfig) {
        if arch.ioapic_base == 0 || arch.ioapic_size == 0 {
            return;
        }
        self.mmio_region_register(
            arch.ioapic_base,
            arch.ioapic_size,
            mmio_ioapic_handler,
            arch.ioapic_base,
        );
    }
}

fn mmio_ioapic_handler(mmio: &mut MMIOAccess, _: usize) -> HvResult {
    if mmio.is_write {
        VIRT_IOAPIC
            .get()
            .unwrap()
            .write(mmio.address, mmio.value as _, mmio.size)
    } else {
        mmio.value = VIRT_IOAPIC.get().unwrap().read(mmio.address).unwrap() as _;
        Ok(())
    }
}

unsafe fn configure_gsi_from_raw(irq: u8, raw: u64) {
    // info!("irq={:x} {:x}", irq, raw);
    let mut io_apic = IO_APIC.lock();
    io_apic.set_table_entry(irq, core::mem::transmute(raw));
}

pub fn init_ioapic() {
    // println!("Initializing I/O APIC...");
    unsafe {
        Port::<u8>::new(0x20).write(0xff);
        Port::<u8>::new(0xa0).write(0xff);
    }
}

pub fn init_virt_ioapic(max_zones: usize) {
    VIRT_IOAPIC.call_once(|| VirtIoApic::new(max_zones));
}

pub fn ioapic_inject_irq(irq: u8, allow_repeat: bool) {
    VIRT_IOAPIC.get().unwrap().trigger(irq as _, allow_repeat);
}

/// When a non-root zone starts on a set of CPUs, ensure critical physical
/// interrupts (UART, etc.) are not routed to those CPUs. If they are, re-route
/// them to CPU 0 which stays in the root zone.  Without this, zone0 can become
/// unresponsive because physical interrupts get injected into a guest that has
/// no handler for them.
pub fn ioapic_reroute_from_cpus(cpu_set: &crate::cpu_data::CpuSet) {
    // Critical IRQs that the root zone needs for interactive console.
    const CRITICAL_IRQS: &[u8] = &[irqs::UART_COM1_IRQ];

    let mut io_apic = IO_APIC.lock();
    for &irq in CRITICAL_IRQS {
        // table_entry returns RedirectionTableEntry, transmute to u64 for
        // bit-field manipulation.
        let entry = unsafe { io_apic.table_entry(irq) };
        let raw: u64 = unsafe { core::mem::transmute(entry) };
        let dest_apic_id = raw.get_bits(56..=63) as usize;
        let dest_cpu = get_cpu_id(dest_apic_id);
        if cpu_set.bitmap & (1u64 << dest_cpu) != 0 {
            // Re-route to CPU 0 which is always in the root zone.
            let cpu0_apic_id = get_apic_id(0) as u64;
            let mut new_raw = raw;
            new_raw.set_bits(56..=63, cpu0_apic_id);
            let new_entry = unsafe { core::mem::transmute(new_raw) };
            unsafe { io_apic.set_table_entry(irq, new_entry) };
            warn!(
                "ioapic: rerouted IRQ {} from CPU {} (APIC {:#x}) to CPU 0 (APIC {:#x})",
                irq, dest_cpu, dest_apic_id, cpu0_apic_id
            );
        }
    }
}

pub fn get_irq_cpu(irq: usize, zone_id: usize) -> usize {
    VIRT_IOAPIC
        .get()
        .unwrap()
        .get_irq_cpu(irq, zone_id)
        .unwrap_or_else(|| {
            warn!(
                "get_irq_cpu: IRQ {} out of range (max {}) for zone {}, falling back to CPU 0",
                irq,
                IOAPIC_MAX_REDIRECT_ENTRIES,
                zone_id
            );
            0
        })
}
