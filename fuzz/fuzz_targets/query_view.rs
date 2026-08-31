#![no_main]

use blackhole::query::QueryView;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|packet: &[u8]| {
    let _ = QueryView::parse(packet);
});
