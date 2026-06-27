use prometheus::register_int_gauge;

pub fn set_boot_success(success: bool) {
    register_int_gauge!(
        "zns_mint_boot_success",
        "Boot success, 1 for success and 0 for failure"
    )
    .unwrap()
    .set(if success { 1 } else { 0 });
}
