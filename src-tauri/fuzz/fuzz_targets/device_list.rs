#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sesame_lib::sync_fuzz::device_list(data);
});
