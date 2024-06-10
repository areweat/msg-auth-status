#![no_main]

use libfuzzer_sys::fuzz_target;

use msg_auth_status::alloc::DkimSignatures;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
});
