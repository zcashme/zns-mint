use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use dudect_bencher::rand::RngExt;

// We need to test the auth module's lowercase_hex and the treasury memo module's decode_otp.
// Wait, these functions are private. Let's just copy them here for testing.

fn lowercase_hex(secret: &[u8; 16]) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    for (index, byte) in secret.iter().copied().enumerate() {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        encoded[index * 2] = hi + 48 + (((hi + 6) >> 4) * 39);
        encoded[index * 2 + 1] = lo + 48 + (((lo + 6) >> 4) * 39);
    }
    encoded
}

fn bench_lowercase_hex(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<[u8; 16]> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..100_000 {
        if rng.random::<bool>() {
            // Left: All zeros (hi=0, lo=0 -> digits)
            inputs.push([0u8; 16]);
            classes.push(Class::Left);
        } else {
            // Right: All 255 (hi=15, lo=15 -> letters)
            inputs.push([255u8; 16]);
            classes.push(Class::Right);
        }
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || lowercase_hex(&input));
    }
}

fn decode_otp(s: &str) -> bool {
    if s.len() != 32 {
        return false;
    }
    let mut valid = 1u8;
    let mut result = [0u8; 16];
    let bytes = s.as_bytes();
    for i in 0..16 {
        let mut byte = 0u8;
        for j in 0..2 {
            let b = bytes[i * 2 + j];
            let is_digit = (b.wrapping_sub(b'0') <= 9) as u8;
            let is_hex = (b.wrapping_sub(b'a') <= 5) as u8;
            valid &= is_digit | is_hex;
            
            let val = is_digit.wrapping_mul(b.wrapping_sub(b'0'))
                | is_hex.wrapping_mul(b.wrapping_sub(b'a').wrapping_add(10));
            
            if j == 0 {
                byte |= val << 4;
            } else {
                byte |= val;
            }
        }
        result[i] = byte;
    }
    valid == 1
}

fn bench_decode_otp(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<String> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..100_000 {
        if rng.random::<bool>() {
            // Left: valid digits
            inputs.push("01234567890123456789012345678901".to_string());
            classes.push(Class::Left);
        } else {
            // Right: valid letters
            inputs.push("abcdefabcdefabcdefabcdefabcdefab".to_string());
            classes.push(Class::Right);
        }
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || decode_otp(&input));
    }
}

ctbench_main!(bench_lowercase_hex, bench_decode_otp);
