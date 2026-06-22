#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    lux::fuzz_api::fuzz_table_query(data);
});
