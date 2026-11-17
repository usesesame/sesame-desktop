use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub struct ApprovalSlot {
    taken: Arc<AtomicBool>,
}

pub struct SlotClaim {
    taken: Arc<AtomicBool>,
}

impl ApprovalSlot {
    pub fn claim(&self) -> Option<SlotClaim> {
        self.taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| SlotClaim {
                taken: Arc::clone(&self.taken),
            })
    }

    pub fn is_taken(&self) -> bool {
        self.taken.load(Ordering::Acquire)
    }
}

impl Drop for SlotClaim {
    fn drop(&mut self) {
        self.taken.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_claim_holds_the_slot_until_it_is_dropped() {
        let slot = ApprovalSlot::default();
        let shared = slot.clone();
        let first = slot.claim().expect("a free slot");
        assert!(shared.claim().is_none());
        assert!(shared.is_taken());
        drop(first);
        assert!(!slot.is_taken());
        assert!(shared.claim().is_some());
    }
}
