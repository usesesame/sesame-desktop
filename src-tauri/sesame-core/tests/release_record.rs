use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use sesame_core::api::create_vault;
use sesame_core::release_record::{
    damaged_path, damaged_paths, record_path, Appended, EntryKind, FieldKind, MatchKind, Outcome,
    RecordEntry, RecordNotice, RecordState, ReleaseDraft, COMPACT_AT, LOCKED_QUEUE_LIMIT,
    MAX_ENTRIES, MAX_RECORD_FILE_BYTES, REFUSALS_PER_HOUR,
};
use sesame_core::storage::{
    persist_session, replace_recovery_kit_for_session, RECOVERY_REPLACEMENT_DELAY_SECS,
};
use sesame_core::{random_id, UnlockedVault};

const PASSWORD: &str = "fictional master password";
const START: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

struct Fixture {
    directory: PathBuf,
    session: UnlockedVault,
    clock: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("sesame-record-{}", random_id()));
        fs::create_dir_all(&directory).expect("test directory");
        let path = directory.join("vault.sesame");
        let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let mut session = UnlockedVault::from_opened(path, &opened).expect("session");
        session.setup_complete = true;
        persist_session(&mut session).expect("initial save");
        Self {
            directory,
            session,
            clock: Arc::new(AtomicU64::new(START)),
        }
    }

    fn state(&self) -> RecordState {
        let state = RecordState::default();
        let clock = Arc::clone(&self.clock);
        state.set_clock(Arc::new(move || clock.load(Ordering::SeqCst)));
        state
    }

    fn advance(&self, seconds: u64) {
        self.clock.fetch_add(seconds, Ordering::SeqCst);
    }

    fn file(&self) -> PathBuf {
        record_path(&self.session.path)
    }

    fn lines(&self) -> Vec<Vec<u8>> {
        let bytes = fs::read(self.file()).expect("record bytes");
        bytes
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn write_lines(&self, lines: &[Vec<u8>]) {
        fs::write(self.file(), lines.concat()).expect("rewritten record");
    }

    fn reopen(&self) -> (RecordState, Vec<RecordEntry>) {
        let state = self.state();
        let entries = state.entries(&self.session).expect("entries");
        (state, entries)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn fill(host: &str, item: &str) -> ReleaseDraft {
    ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Released)
        .item(item, "login")
        .field("password")
        .field("username")
        .host(host)
        .match_kind(Some(MatchKind::Exact))
}

fn seeded(fixture: &Fixture, count: usize) -> RecordState {
    let state = fixture.state();
    for index in 0..count {
        assert_eq!(
            state.append(
                &fixture.session,
                fill("example.com", &format!("item-{index}"))
            ),
            Appended::Written
        );
        fixture.advance(1);
    }
    state
}

fn releases(entries: &[RecordEntry]) -> Vec<&RecordEntry> {
    entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::BrowserFill)
        .collect()
}

#[test]
fn entries_survive_a_write_and_a_fresh_read() {
    let fixture = Fixture::new();
    seeded(&fixture, 3);

    let (state, entries) = fixture.reopen();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].item_id.as_deref(), Some("item-1"));
    assert_eq!(entries[1].host.as_deref(), Some("example.com"));
    assert_eq!(
        entries[1].fields,
        vec![FieldKind::Password, FieldKind::Username]
    );
    assert_eq!(entries[1].seq, 1);
    assert_eq!(entries[2].at, START + 2);
    assert_eq!(state.status().notice, None);
}

#[test]
fn every_entry_line_has_the_same_length_and_the_file_shows_no_plaintext() {
    let fixture = Fixture::new();
    let state = fixture.state();
    state.append(&fixture.session, fill("a.example.com", "short"));
    state.append(
        &fixture.session,
        fill(
            &format!("{}.example.com", "b".repeat(200)),
            &"x".repeat(120),
        ),
    );
    state.append(
        &fixture.session,
        ReleaseDraft::new(EntryKind::CsvExport, Outcome::Released).count(40),
    );

    let lines = fixture.lines();
    assert_eq!(lines.len(), 4);
    assert!(lines[1..].iter().all(|line| line.len() == lines[1].len()));
    let raw = String::from_utf8(lines.concat()).expect("utf8 record");
    let vault_id = fixture.session.vault_id().expect("vault id");
    for visible in ["example.com", "short", "login", "password", vault_id] {
        assert!(!raw.contains(visible), "the file shows {visible}");
    }
}

#[test]
fn a_torn_final_line_keeps_the_prefix_and_says_a_write_was_interrupted() {
    let fixture = Fixture::new();
    seeded(&fixture, 3);
    let mut lines = fixture.lines();
    let last = lines.len() - 1;
    let keep = lines[last].len() / 2;
    lines[last].truncate(keep);
    fixture.write_lines(&lines);

    let (state, entries) = fixture.reopen();

    assert_eq!(releases(&entries).len(), 2);
    assert_eq!(
        entries.last().map(|entry| entry.kind),
        Some(EntryKind::Interrupted)
    );
    assert_eq!(state.status().notice, Some(RecordNotice::Interrupted));
    assert!(!damaged_path(&fixture.session.path).exists());
}

#[test]
fn a_cut_at_a_line_boundary_is_not_detected() {
    let fixture = Fixture::new();
    seeded(&fixture, 3);
    let mut lines = fixture.lines();
    lines.pop();
    fixture.write_lines(&lines);

    let (state, entries) = fixture.reopen();

    assert_eq!(releases(&entries).len(), 2);
    assert_eq!(state.status().notice, None);
}

#[test]
fn a_deleted_file_starts_a_new_record_without_failing() {
    let fixture = Fixture::new();
    seeded(&fixture, 2);
    fs::remove_file(fixture.file()).expect("deleted record");

    let (state, entries) = fixture.reopen();

    assert!(entries.is_empty());
    assert_eq!(state.status().notice, None);
    assert!(fixture.file().exists());
}

#[test]
fn a_record_from_another_vault_is_set_aside_as_unreadable() {
    let first = Fixture::new();
    seeded(&first, 2);
    let second = Fixture::new();
    fs::copy(first.file(), second.file()).expect("copied record");

    let (state, entries) = second.reopen();

    assert!(releases(&entries).is_empty());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, EntryKind::Unreadable);
    assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
    assert!(damaged_path(&second.session.path).exists());
}

fn assert_prefix(fixture: &Fixture, kept: usize) {
    let (state, entries) = fixture.reopen();
    assert_eq!(releases(&entries).len(), kept);
    assert_eq!(
        entries.last().map(|entry| entry.kind),
        Some(EntryKind::Unreadable)
    );
    assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
    assert!(damaged_path(&fixture.session.path).exists());
}

#[test]
fn reordered_entries_keep_only_the_prefix_before_the_swap() {
    let fixture = Fixture::new();
    seeded(&fixture, 4);
    let mut lines = fixture.lines();
    lines.swap(2, 3);
    fixture.write_lines(&lines);

    assert_prefix(&fixture, 1);
}

#[test]
fn a_removed_middle_entry_breaks_the_chain() {
    let fixture = Fixture::new();
    seeded(&fixture, 4);
    let mut lines = fixture.lines();
    lines.remove(2);
    fixture.write_lines(&lines);

    assert_prefix(&fixture, 1);
}

#[test]
fn a_duplicated_entry_breaks_the_chain() {
    let fixture = Fixture::new();
    seeded(&fixture, 3);
    let mut lines = fixture.lines();
    let copy = lines[2].clone();
    lines.insert(3, copy);
    fixture.write_lines(&lines);

    assert_prefix(&fixture, 2);
}

#[test]
fn an_entry_from_an_earlier_generation_cannot_be_spliced_in() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 3);
    let earlier = fixture.lines();
    state.clear(&fixture.session).expect("cleared");
    let mut lines = fixture.lines();
    lines.push(earlier[1].clone());
    fixture.write_lines(&lines);

    let (state, entries) = fixture.reopen();

    assert_eq!(entries[0].kind, EntryKind::Cleared);
    assert!(releases(&entries).is_empty());
    assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
}

fn flip(fixture: &Fixture, line: usize, offset_from_end: usize) {
    let mut lines = fixture.lines();
    let target = lines[line].len() - offset_from_end;
    lines[line][target] ^= 0x01;
    fixture.write_lines(&lines);
}

#[test]
fn a_flipped_bit_in_the_header_makes_the_whole_record_unreadable() {
    let fixture = Fixture::new();
    seeded(&fixture, 2);
    flip(&fixture, 0, 6);

    let (state, entries) = fixture.reopen();

    assert!(releases(&entries).is_empty());
    assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
}

#[test]
fn a_flipped_bit_in_a_nonce_or_ciphertext_keeps_the_prefix() {
    for (line, offset) in [(2_usize, 0_usize), (2, 1)] {
        let fixture = Fixture::new();
        seeded(&fixture, 3);
        let mut lines = fixture.lines();
        let position = if offset == 0 {
            lines[line]
                .windows(9)
                .position(|window| window == b"\"nonce\":\"")
                .expect("nonce")
                + 12
        } else {
            lines[line].len() - 10
        };
        lines[line][position] ^= 0x01;
        fixture.write_lines(&lines);

        assert_prefix(&fixture, 1);
    }
}

#[test]
fn a_flipped_bit_in_the_last_entry_keeps_everything_before_it() {
    let fixture = Fixture::new();
    seeded(&fixture, 3);
    flip(&fixture, 3, 10);

    assert_prefix(&fixture, 2);
}

#[test]
fn malformed_lines_never_panic_and_keep_the_prefix() {
    let malformed: [&[u8]; 4] = [
        b"{\"nonce\":\"%%%\",\"ciphertext\":\"%%%\"}\n",
        b"not json at all\n",
        b"{\"nonce\":1}\n",
        b"\n",
    ];
    for line in malformed {
        let fixture = Fixture::new();
        seeded(&fixture, 2);
        let mut lines = fixture.lines();
        lines.push(line.to_vec());
        fixture.write_lines(&lines);

        assert_prefix(&fixture, 2);
    }
    let fixture = Fixture::new();
    seeded(&fixture, 1);
    let mut lines = fixture.lines();
    let mut overlong = vec![b'a'; 2 * 1024 * 1024];
    overlong.push(b'\n');
    lines.push(overlong);
    fixture.write_lines(&lines);
    assert_prefix(&fixture, 1);
}

#[test]
fn an_oversized_or_empty_file_is_unreadable_without_reading_it_all() {
    for size in [MAX_RECORD_FILE_BYTES + 1, 0] {
        let fixture = Fixture::new();
        let file = fs::File::create(fixture.file()).expect("record file");
        file.set_len(size).expect("sized record");
        drop(file);

        let (state, entries) = fixture.reopen();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::Unreadable);
        assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
    }
}

fn rotate(session: &mut UnlockedVault) {
    replace_recovery_kit_for_session(
        session,
        PASSWORD,
        START,
        START + RECOVERY_REPLACEMENT_DELAY_SECS,
        false,
    )
    .expect("rotated vault key");
}

#[test]
fn a_vault_key_change_reseals_the_record_under_the_new_key() {
    let mut fixture = Fixture::new();
    let state = seeded(&fixture, 2);
    let before = fixture.lines()[0].clone();
    let old_vault = fs::read(&fixture.session.path).expect("old vault");

    rotate(&mut fixture.session);
    assert_eq!(
        state.append(&fixture.session, fill("example.org", "item-9")),
        Appended::Written
    );

    assert_ne!(fixture.lines()[0], before);
    let (state, entries) = fixture.reopen();
    assert_eq!(releases(&entries).len(), 3);
    assert_eq!(state.status().notice, None);

    let restored_directory = fixture.directory.join("restored");
    fs::create_dir_all(&restored_directory).expect("restored directory");
    let restored_path = restored_directory.join("vault.sesame");
    fs::write(&restored_path, old_vault).expect("restored vault");
    fs::copy(fixture.file(), record_path(&restored_path)).expect("record beside the restore");
    let file: sesame_core::VaultFile =
        serde_json::from_slice(&fs::read(&restored_path).expect("vault bytes")).expect("file");
    let opened =
        sesame_core::api::open_vault_with_password(&file, PASSWORD).expect("old vault opens");
    let old_session = UnlockedVault::from_opened(restored_path, &opened).expect("old session");
    let old_state = fixture.state();
    let entries = old_state.entries(&old_session).expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, EntryKind::Unreadable);
    assert_eq!(old_state.status().notice, Some(RecordNotice::Unreadable));
}

#[test]
fn retention_removes_old_entries_and_keeps_a_valid_chain() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 3);
    fixture.advance(40 * DAY);
    state.append(&fixture.session, fill("example.net", "item-new"));
    state.set_retention_days(30);
    state.apply_retention(&fixture.session).expect("trimmed");

    let (state, entries) = fixture.reopen();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].item_id.as_deref(), Some("item-new"));
    assert_eq!(entries[0].seq, 0);
    assert_eq!(state.status().notice, None);
}

#[test]
fn the_entry_cap_trims_the_oldest_entries() {
    let fixture = Fixture::new();
    let state = fixture.state();
    for index in 0..COMPACT_AT {
        state.append(
            &fixture.session,
            ReleaseDraft::new(EntryKind::Copy, Outcome::Released)
                .item(&format!("i{index}"), "login"),
        );
    }

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), MAX_ENTRIES);
    assert_eq!(
        entries.last().and_then(|entry| entry.item_id.as_deref()),
        Some(format!("i{}", COMPACT_AT - 1).as_str())
    );
    assert_eq!(entries[0].seq, 0);
}

#[test]
fn clearing_leaves_a_single_cleared_entry() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 5);

    state.clear(&fixture.session).expect("cleared");

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, EntryKind::Cleared);
    assert_eq!(entries[0].count, 5);
}

#[test]
fn appending_never_touches_the_vault_file() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.session.path).expect("vault bytes");
    let revision = fixture.session.snapshot().revision;

    seeded(&fixture, 3);

    assert_eq!(
        fs::read(&fixture.session.path).expect("vault bytes"),
        before
    );
    assert_eq!(fixture.session.snapshot().revision, revision);
}

fn block_record(file: &Path) {
    fs::remove_file(file).expect("removed record");
    fs::create_dir(file).expect("record path blocked");
}

#[test]
fn a_failed_write_is_kept_in_memory_and_retried() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 1);
    block_record(&fixture.file());

    assert_eq!(
        state.append(&fixture.session, fill("example.com", "item-late")),
        Appended::Deferred
    );
    assert_eq!(state.status().unwritten, 1);

    fs::remove_dir(fixture.file()).expect("unblocked record");
    assert_eq!(
        state.append(&fixture.session, fill("example.com", "item-after")),
        Appended::Written
    );
    assert_eq!(state.status().unwritten, 0);

    let (_, entries) = fixture.reopen();
    let late = entries
        .iter()
        .find(|entry| entry.item_id.as_deref() == Some("item-late"))
        .expect("late entry");
    assert!(late.late);
    assert!(entries
        .iter()
        .any(|entry| entry.kind == EntryKind::FileChanged));
    assert!(entries
        .iter()
        .any(|entry| entry.item_id.as_deref() == Some("item-0")));
}

#[test]
fn requests_while_locked_are_queued_with_host_and_time_only() {
    let fixture = Fixture::new();
    let state = fixture.state();
    for index in 0..(LOCKED_QUEUE_LIMIT + 10) {
        state.append_locked(
            ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Locked)
                .item("item-x", "login")
                .host(&format!("site{index}.example.com")),
        );
    }
    state.append_locked(
        ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Locked).host("site0.example.com"),
    );

    state.open(&fixture.session).expect("opened");

    let (_, entries) = fixture.reopen();
    let locked: Vec<_> = entries
        .iter()
        .filter(|entry| entry.outcome == Outcome::Locked)
        .collect();
    assert_eq!(locked.len(), LOCKED_QUEUE_LIMIT);
    assert!(locked
        .iter()
        .all(|entry| entry.late && entry.item_id.is_none()));
    assert_eq!(locked[0].count, 2);
    let overflow = entries
        .iter()
        .find(|entry| entry.kind == EntryKind::LockedOverflow)
        .expect("overflow entry");
    assert_eq!(overflow.count, 10);
}

#[test]
fn a_flood_from_one_page_is_counted_into_one_entry() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let denied =
        || ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Busy).host("flood.example.com");
    assert_eq!(state.append(&fixture.session, denied()), Appended::Written);
    for _ in 0..10_000 {
        assert_eq!(state.append(&fixture.session, denied()), Appended::Counted);
    }
    assert_eq!(fixture.lines().len(), 2);

    fixture.advance(61);
    state.entries(&fixture.session).expect("flushed");

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].count, 10_000);
}

#[test]
fn refusals_from_rotating_hosts_stop_at_the_hourly_limit() {
    let fixture = Fixture::new();
    let state = fixture.state();
    for index in 0..(REFUSALS_PER_HOUR + 80) {
        state.append(
            &fixture.session,
            ReleaseDraft::new(EntryKind::BrowserFill, Outcome::NoMatch)
                .host(&format!("h{index}.example.com")),
        );
    }
    assert_eq!(fixture.lines().len(), REFUSALS_PER_HOUR + 1);

    fixture.advance(3_601);
    state.entries(&fixture.session).expect("flushed");

    let (_, entries) = fixture.reopen();
    let limit = entries
        .iter()
        .find(|entry| entry.kind == EntryKind::RefusalLimit)
        .expect("limit entry");
    assert_eq!(limit.count, 80);
}

#[test]
fn releases_are_never_coalesced() {
    let fixture = Fixture::new();
    let state = fixture.state();
    for _ in 0..5 {
        assert_eq!(
            state.append(&fixture.session, fill("example.com", "item-1")),
            Appended::Written
        );
    }
    assert_eq!(fixture.lines().len(), 6);
}

#[test]
fn closing_writes_pending_counts_before_the_key_is_dropped() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let denied = || ReleaseDraft::new(EntryKind::BrowserTotp, Outcome::Denied).host("example.com");
    state.append(&fixture.session, denied());
    state.append(&fixture.session, denied());
    state.close(Some(&fixture.session));

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].count, 1);
    assert!(!state.status().open);
}

#[test]
fn odd_item_ids_and_hosts_are_bounded() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let odd = format!("{}\"\\é", "z".repeat(300));
    state.append(
        &fixture.session,
        ReleaseDraft::new(EntryKind::Reveal, Outcome::Released)
            .item(&odd, "login")
            .host(&format!("{}\u{7}", "h".repeat(400))),
    );

    let (_, entries) = fixture.reopen();
    assert!(entries[0]
        .item_id
        .as_deref()
        .is_some_and(|id| id.starts_with("sha256:")));
    assert_eq!(entries[0].host.as_deref().map(str::len), Some(253));
}

#[cfg(unix)]
#[test]
fn a_record_that_cannot_be_read_at_unlock_is_left_in_place_and_tried_again() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    seeded(&fixture, 3);
    fs::set_permissions(fixture.file(), fs::Permissions::from_mode(0o000)).expect("mode");

    let state = fixture.state();
    assert!(state.entries(&fixture.session).is_err());
    assert_eq!(
        state.append(&fixture.session, fill("example.com", "item-late")),
        Appended::Deferred
    );
    assert!(!state.status().open);

    fs::set_permissions(fixture.file(), fs::Permissions::from_mode(0o600)).expect("mode");
    assert!(damaged_paths(&fixture.session.path)
        .iter()
        .all(|copy| !copy.exists()));
    let entries = state.entries(&fixture.session).expect("entries");
    assert_eq!(releases(&entries).len(), 4);
    assert_eq!(state.status().notice, None);
}

#[test]
fn a_second_damaged_record_never_replaces_the_first() {
    let fixture = Fixture::new();
    let copies = damaged_paths(&fixture.session.path);
    assert_eq!(copies[0], damaged_path(&fixture.session.path));
    for round in 0..(copies.len() + 1) {
        fs::write(fixture.file(), format!("damaged record {round}\n")).expect("damaged");
        let (state, _) = fixture.reopen();
        assert_eq!(state.status().notice, Some(RecordNotice::Unreadable));
    }

    for (round, copy) in copies.iter().enumerate() {
        assert_eq!(
            fs::read_to_string(copy).expect("kept copy"),
            format!("damaged record {round}\n")
        );
    }
}

#[test]
fn a_window_that_expires_between_two_clock_reads_keeps_its_count() {
    let fixture = Fixture::new();
    let state = RecordState::default();
    let now = Arc::new(AtomicU64::new(START));
    let early = Arc::new(AtomicBool::new(false));
    {
        let now = Arc::clone(&now);
        let early = Arc::clone(&early);
        state.set_clock(Arc::new(move || {
            let current = now.load(Ordering::SeqCst);
            if early.swap(false, Ordering::SeqCst) {
                current - 1
            } else {
                current
            }
        }));
    }
    let denied = || ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("example.com");
    assert_eq!(state.append(&fixture.session, denied()), Appended::Written);
    assert_eq!(state.append(&fixture.session, denied()), Appended::Counted);

    now.store(START + 60, Ordering::SeqCst);
    early.store(true, Ordering::SeqCst);
    state.append(&fixture.session, denied());
    now.store(START + 200, Ordering::SeqCst);
    let entries = state.entries(&fixture.session).expect("entries");

    assert_eq!(entries.iter().map(|entry| entry.count).sum::<u32>(), 3);
}

#[test]
fn an_entry_that_cannot_be_encoded_is_dropped_and_counted() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let oversized = ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Lookalike)
        .item(&"i".repeat(128), &"k".repeat(32))
        .fields([
            "password",
            "username",
            "email",
            "totp",
            "backupCodes",
            "field:1",
            "legacy1",
            "number",
            "cardholderName",
            "expiry",
            "securityCode",
            "fullName",
        ])
        .host(&format!("{}.example.com", "h".repeat(240)))
        .similar_to(&format!("{}.example.org", "s".repeat(240)))
        .match_kind(Some(MatchKind::WwwAlias));

    state.append(&fixture.session, oversized);
    assert_eq!(
        state.append(&fixture.session, fill("example.com", "item-after")),
        Appended::Written
    );

    let (_, entries) = fixture.reopen();
    assert_eq!(releases(&entries).len(), 1);
    let lost = entries
        .iter()
        .find(|entry| entry.kind == EntryKind::WritesLost)
        .expect("lost entry");
    assert_eq!(lost.count, 1);
    assert_eq!(state.status().unwritten, 0);
}

#[test]
fn the_mark_moves_only_when_the_record_changes() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let denied = || ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Busy).host("example.com");
    let before = state.mark();
    state.append(&fixture.session, denied());
    let written = state.mark();
    assert_ne!(written, before);

    assert_eq!(state.append(&fixture.session, denied()), Appended::Counted);
    state.append_locked(denied());

    assert_eq!(state.mark(), written);
}

#[test]
fn shortening_retention_leaves_an_entry_with_the_count() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 3);
    fixture.advance(40 * DAY);
    state.append(&fixture.session, fill("example.net", "item-new"));

    assert_eq!(state.shorten_retention(&fixture.session, 30), Ok(3));

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].item_id.as_deref(), Some("item-new"));
    assert_eq!(entries[1].kind, EntryKind::RetentionShortened);
    assert_eq!(entries[1].count, 3);
    assert_eq!(state.retention_days(), 30);
}

#[test]
fn shortening_retention_with_nothing_old_adds_no_entry() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 2);

    assert_eq!(state.shorten_retention(&fixture.session, 30), Ok(0));

    let (_, entries) = fixture.reopen();
    assert_eq!(entries.len(), 2);
}

#[test]
fn discarding_drops_queued_counted_and_unwritten_entries() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 1);
    let denied = || ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("gone.example");
    state.append(&fixture.session, denied());
    state.append(&fixture.session, denied());
    state.append_locked(denied());
    block_record(&fixture.file());
    state.append(&fixture.session, fill("gone.example", "item-unwritten"));
    assert!(state.status().unwritten > 0);

    state.discard();
    fs::remove_dir(fixture.file()).expect("unblocked record");

    assert_eq!(state.status().unwritten, 0);
    let entries = state.entries(&fixture.session).expect("entries");
    assert!(entries
        .iter()
        .all(|entry| entry.host.as_deref() != Some("gone.example")));
}

#[test]
fn a_failed_rewrite_while_shortening_retention_changes_nothing() {
    let fixture = Fixture::new();
    let state = seeded(&fixture, 3);
    fixture.advance(40 * DAY);
    state.append(&fixture.session, fill("example.net", "item-new"));
    block_record(&fixture.file());

    assert!(state.shorten_retention(&fixture.session, 30).is_err());
    assert_eq!(state.retention_days(), 180);

    fs::remove_dir(fixture.file()).expect("unblocked record");
    assert_eq!(state.entries(&fixture.session).expect("entries").len(), 4);
    let (_, entries) = fixture.reopen();
    assert_eq!(releases(&entries).len(), 4);
    assert!(entries
        .iter()
        .all(|entry| entry.kind != EntryKind::RetentionShortened));
}

#[test]
fn entries_removed_by_a_shorter_retention_are_counted_even_when_the_flush_compacts() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let old = 100;
    for index in 0..(COMPACT_AT - old - 2) {
        state.append(
            &fixture.session,
            ReleaseDraft::new(EntryKind::Copy, Outcome::Released)
                .item(&format!("recent-{index}"), "login"),
        );
    }
    for index in 0..old {
        let mut draft = ReleaseDraft::new(EntryKind::Copy, Outcome::Released)
            .item(&format!("old-{index}"), "login");
        draft.at = Some(START - 40 * DAY);
        state.append(&fixture.session, draft);
    }
    let denied = || ReleaseDraft::new(EntryKind::BrowserFill, Outcome::Denied).host("example.com");
    assert_eq!(state.append(&fixture.session, denied()), Appended::Written);
    assert_eq!(state.append(&fixture.session, denied()), Appended::Counted);
    fixture.advance(61);

    assert_eq!(state.shorten_retention(&fixture.session, 30), Ok(old));

    let (_, entries) = fixture.reopen();
    let marker = entries
        .iter()
        .find(|entry| entry.kind == EntryKind::RetentionShortened)
        .expect("retention entry");
    assert_eq!(marker.count as usize, old);
    assert!(entries.iter().all(|entry| !entry
        .item_id
        .as_deref()
        .is_some_and(|id| id.starts_with("old-"))));
}

#[test]
fn something_other_than_a_file_at_the_record_path_is_left_in_place() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.file()).expect("directory in place of the record");

    let state = fixture.state();
    assert!(state.entries(&fixture.session).is_err());
    assert_eq!(
        state.append(&fixture.session, fill("example.com", "item-late")),
        Appended::Deferred
    );

    assert!(fixture.file().is_dir());
    assert!(damaged_paths(&fixture.session.path)
        .iter()
        .all(|copy| !copy.exists()));
}
