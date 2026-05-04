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

pub mod ioapic;
pub mod lapic;

use crate::{
    arch::{acpi, cpu::this_cpu_id, idt, iommu, ipi, msr, pio, vmcs::Vmcs},
    consts::{MAX_CPU_NUM, MAX_ZONE_NUM},
    zone::Zone,
};
use alloc::{collections::vec_deque::VecDeque, vec::Vec};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use ioapic::ioapic_inject_irq;
use spin::{Mutex, Once};

static PENDING_VECTORS: Once<PendingVectors> = Once::new();

struct InnerPendingVectors {
    pub queue: VecDeque<(u8, Option<u32>)>,
    pub has_eoi: bool,
    /// Number of consecutive check_pending_vectors calls where
    /// has_eoi was false while vectors were pending (reset on EOI).
    pub eoi_stuck_count: u64,
}

struct PendingVectors {
    inner: Vec<Mutex<InnerPendingVectors>>,
}

impl PendingVectors {
    fn new(max_cpus: usize) -> Self {
        let mut vs = vec![];
        for _ in 0..max_cpus {
            let v = Mutex::new(InnerPendingVectors {
                queue: VecDeque::new(),
                has_eoi: true,
                eoi_stuck_count: 0,
            });
            vs.push(v);
        }
        Self { inner: vs }
    }

    /// Returns true if the vector was added to the queue, false if it was
    /// dropped as a duplicate.  Callers should only send a wakeup IPI when
    /// the vector was actually added — re-sending IPIs on every duplicate
    /// floods the destination CPU with spurious VMEXITs.
    fn add_vector(&self, cpu_id: usize, vector: u8, err_code: Option<u32>, allow_repeat: bool) -> bool {
        let mut vectors = self.inner.get(cpu_id).unwrap().lock();
        if vectors.queue.len() > 10 {
            warn!("too many pending vectors! cnt: {:x?}", vectors.queue.len());
        }
        if allow_repeat || !vectors.queue.contains(&(vector, err_code)) {
            vectors.queue.push_back((vector, err_code));
            true
        } else {
            false
        }
    }

    fn check_pending_vectors(&self, cpu_id: usize) -> bool {
        let mut vectors = self.inner.get(cpu_id).unwrap().lock();

        let front = vectors.queue.front().copied();
        if let Some((vector, err_code)) = front {
            let is_exception = vector < 32;
            let allow_interrupt = Vmcs::allow_interrupt().unwrap() && vectors.has_eoi;
            if is_exception || allow_interrupt {
                Vmcs::inject_interrupt(vector, err_code).unwrap();
                // Exceptions (vector < 32) don't need EOI — they return via IRET.
                // Only set has_eoi = false for hardware interrupts that require EOI.
                if !is_exception {
                    vectors.has_eoi = false;
                }
                vectors.queue.pop_front();
                vectors.eoi_stuck_count = 0;
                return true;
            } else if vectors.has_eoi {
                // interrupts are blocked, enable interrupt-window exiting.
                Vmcs::set_interrupt_window(true).unwrap();
            } else {
                // has_eoi is false: previous interrupt not yet EOI'd.
                // This is normal for a few iterations while the guest processes
                // the interrupt. Only log/discard if it persists.
                vectors.eoi_stuck_count += 1;
                // Enable interrupt-window exiting so the pending vector
                // can be injected as soon as the guest re-enables interrupts.
                Vmcs::set_interrupt_window(true).unwrap();
                // Watchdog: only discard if EOI hasn't arrived after a very
                // large number of checks.  A few dozen is normal processing delay.
                if vectors.eoi_stuck_count >= 5000 {
                    warn!("[EOI_STUCK] cpu{}: discarding stuck vector={:#x} after {} checks ({} queued remain)",
                          cpu_id, vector, vectors.eoi_stuck_count, vectors.queue.len() - 1);
                    vectors.queue.pop_front();
                    vectors.has_eoi = true;
                    vectors.eoi_stuck_count = 0;
                    // Send physical EOI for the discarded interrupt to clear
                    // the ISR so the LAPIC can accept new interrupts.
                    unsafe { lapic::VirtLocalApic::phys_local_apic().end_of_interrupt() };
                }
            }
        }
        false
    }

    fn pop_vector(&self, cpu_id: usize) {
        let mut vectors = self.inner.get(cpu_id).unwrap().lock();
        let was_significantly_stuck = vectors.eoi_stuck_count > 100;
        vectors.has_eoi = true;
        vectors.eoi_stuck_count = 0;
        // Log once per CPU to confirm EOI mechanism works, and on recovery
        // from a genuinely stuck state (not just normal processing delay).
        static EOI_COUNT: [AtomicU64; MAX_CPU_NUM] = [const { AtomicU64::new(0) }; MAX_CPU_NUM];
        let ec = EOI_COUNT[cpu_id].fetch_add(1, Ordering::Relaxed);
        if ec == 0 {
            info!("[EOI] cpu{}: first EOI received", cpu_id);
        } else if was_significantly_stuck {
            warn!("[EOI_STUCK] cpu{}: EOI recovered after long delay (total EOIs={})", cpu_id, ec + 1);
        }
    }

    fn clear_vectors(&self, cpu_id: usize) {
        let mut vectors = self.inner.get(cpu_id).unwrap().lock();
        vectors.queue.clear();
    }
}

pub fn inject_vector(cpu_id: usize, vector: u8, err_code: Option<u32>, allow_repeat: bool) {
    let added = PENDING_VECTORS
        .get()
        .unwrap()
        .add_vector(cpu_id, vector, err_code, allow_repeat);
    // Only send wakeup IPI if the vector was actually added to the queue.
    // Re-sending IPIs on duplicate-dropped vectors floods the destination
    // CPU with spurious VMEXITs, starving it of useful work.
    if added && cpu_id != this_cpu_id() {
        ipi::arch_send_event(cpu_id as _, 0);
    }
}

pub fn check_pending_vectors(cpu_id: usize) -> bool {
    PENDING_VECTORS.get().unwrap().check_pending_vectors(cpu_id)
}

pub fn pop_vector(cpu_id: usize) {
    PENDING_VECTORS.get().unwrap().pop_vector(cpu_id);
}

pub fn clear_vectors(cpu_id: usize) {
    PENDING_VECTORS.get().unwrap().clear_vectors(cpu_id);
}

pub fn enable_irq() {
    unsafe { asm!("sti") };
}

pub fn disable_irq() {
    unsafe { asm!("cli") };
}

pub fn inject_irq(_irq: usize, allow_repeat: bool) {
    ioapic_inject_irq(_irq as _, allow_repeat);
}

pub fn percpu_init() {}

pub fn primary_init_early() {
    ipi::init(MAX_CPU_NUM);
    PENDING_VECTORS.call_once(|| PendingVectors::new(MAX_CPU_NUM));
    ioapic::init_ioapic();
    ioapic::init_virt_ioapic(MAX_ZONE_NUM);
    msr::init_msr_bitmap_map();
    pio::init_pio_bitmap_map();
}

pub fn primary_init_late() {}

impl Zone {
    pub fn arch_irqchip_reset(&self) {
        iommu::clear_dma_translation_tables(self.id);
    }
}
