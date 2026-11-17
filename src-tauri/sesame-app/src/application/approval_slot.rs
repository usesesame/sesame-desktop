use std::sync::{Arc, Mutex, MutexGuard};

type Preempt = Arc<dyn Fn() + Send + Sync>;

enum Holder {
    Browser,
    Terminal(Preempt),
}

#[derive(Default)]
struct SlotState {
    holder: Option<(u64, Holder)>,
    generation: u64,
}

impl SlotState {
    fn take(&mut self, holder: Holder) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.holder = Some((self.generation, holder));
        self.generation
    }
}

#[derive(Clone, Default)]
pub struct ApprovalSlot {
    state: Arc<Mutex<SlotState>>,
}

pub struct SlotClaim {
    state: Arc<Mutex<SlotState>>,
    generation: u64,
}

fn lock(state: &Mutex<SlotState>) -> MutexGuard<'_, SlotState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ApprovalSlot {
    fn claim_with(&self, generation: u64) -> SlotClaim {
        SlotClaim {
            state: Arc::clone(&self.state),
            generation,
        }
    }

    pub fn claim_for_browser(&self) -> Option<SlotClaim> {
        let (generation, preempt) = {
            let mut state = lock(&self.state);
            let preempt = match &state.holder {
                Some((_, Holder::Browser)) => return None,
                Some((_, Holder::Terminal(preempt))) => Some(Arc::clone(preempt)),
                None => None,
            };
            (state.take(Holder::Browser), preempt)
        };
        if let Some(preempt) = preempt {
            preempt();
        }
        Some(self.claim_with(generation))
    }

    pub fn claim_for_terminal(
        &self,
        preempt: impl Fn() + Send + Sync + 'static,
    ) -> Option<SlotClaim> {
        let mut state = lock(&self.state);
        if state.holder.is_some() {
            return None;
        }
        let generation = state.take(Holder::Terminal(Arc::new(preempt)));
        drop(state);
        Some(self.claim_with(generation))
    }

    pub fn is_taken(&self) -> bool {
        lock(&self.state).holder.is_some()
    }

    #[cfg(test)]
    pub fn held_by_browser(&self) -> bool {
        matches!(lock(&self.state).holder, Some((_, Holder::Browser)))
    }
}

impl Drop for SlotClaim {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if state
            .holder
            .as_ref()
            .is_some_and(|(generation, _)| *generation == self.generation)
        {
            state.holder = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn one_claim_holds_the_slot_until_it_is_dropped() {
        let slot = ApprovalSlot::default();
        let shared = slot.clone();
        let first = slot.claim_for_browser().expect("a free slot");
        assert!(shared.claim_for_browser().is_none());
        assert!(shared.claim_for_terminal(|| {}).is_none());
        assert!(shared.is_taken());
        drop(first);
        assert!(!slot.is_taken());
        assert!(shared.claim_for_terminal(|| {}).is_some());
    }

    #[test]
    fn a_browser_claim_preempts_a_terminal_claim_and_keeps_the_slot() {
        let slot = ApprovalSlot::default();
        let preempted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&preempted);
        let terminal = slot
            .claim_for_terminal(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .expect("a free slot");

        let browser = slot.claim_for_browser().expect("the browser goes first");
        assert_eq!(preempted.load(Ordering::SeqCst), 1);
        assert!(slot.held_by_browser());

        drop(terminal);
        assert!(slot.held_by_browser());
        assert!(slot.claim_for_terminal(|| {}).is_none());
        drop(browser);
        assert!(!slot.is_taken());
    }

    #[test]
    fn a_preempt_that_drops_the_terminal_claim_does_not_free_the_browser_claim() {
        let slot = ApprovalSlot::default();
        let held: Arc<Mutex<Option<SlotClaim>>> = Arc::new(Mutex::new(None));
        let inside = Arc::clone(&held);
        let claim = slot
            .claim_for_terminal(move || {
                inside.lock().expect("held").take();
            })
            .expect("a free slot");
        *held.lock().expect("held") = Some(claim);

        let _browser = slot.claim_for_browser().expect("the browser goes first");
        assert!(held.lock().expect("held").is_none());
        assert!(slot.held_by_browser());
    }
}
