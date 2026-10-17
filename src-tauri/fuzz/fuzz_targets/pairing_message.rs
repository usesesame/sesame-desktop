#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sesame_lib::sync_fuzz::pairing_message(data);
});
