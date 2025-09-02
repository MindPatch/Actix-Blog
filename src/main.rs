// semgrep-rust-demo
// Demonstrates several insecure patterns for static analysis / Semgrep demos.
//
// NOTE: These are intentionally insecure patterns *for testing only*. Do not use
// them in production.

use std::collections::HashMap;
use std::env;
use std::process::Command;

fn main() {
    hardcoded_credentials_demo();
    let user_input = " -la / "; // pretend this came from an untrusted source
    command_injection_demo(user_input);

    // unwrap panic demo (common semgrep rule target)
    unwrap_panic_demo();

    // serde unchecked deserialize demo
    let raw = r#"{"is_admin": "true", "name": "attacker"}"#;
    let _ = insecure_deserialize_demo(raw);

    // small unsafe usage demo
    unsafe_demo();
}

/// 1) Hardcoded credential / secret
fn hardcoded_credentials_demo() {
    // <-- Semgrep should flag the literal secret here
    const DB_PASSWORD: &str = "S3cr3tPassw0rd!!";
    println!("Connecting to DB with password: {}", DB_PASSWORD);
}

/// 2) Shelling out with untrusted input (string interpolation into shell)
fn command_injection_demo(user_input: &str) {
    // Dangerous pattern: passing a formatted string to a shell.
    // Semgrep rules often look for `Command::new("sh").arg("-c").arg(format!(...))` patterns.
    let cmd = format!("ls {}", user_input);
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();

    match output {
        Ok(o) => {
            println!("Command ran, status: {}", o.status);
        }
        Err(e) => {
            println!("Failed to run command: {}", e);
        }
    }
}

/// 3) Unwrap on env var / Result (can cause panics or mask errors)
fn unwrap_panic_demo() {
    // If CONFIG not set, this will panic.
    // Semgrep often flags `.unwrap()` or `.expect()` usage.
    let config = env::var("CONFIG").unwrap_or_else(|_| String::from("default-config"));
    println!("Loaded config: {}", config);

    // Another `.unwrap()` example (explicit panic risk)
    let maybe_number: Option<i32> = None;
    // This causes panic at runtime — good for demoing checks for `.unwrap()`.
    if maybe_number.is_some() {
        println!("Number: {}", maybe_number.unwrap());
    }
}

/// 4) Insecure/unchecked deserialization using `serde_json::from_str` + `.unwrap()`
fn insecure_deserialize_demo(body: &str) -> HashMap<String, String> {
    // Common pattern: `serde_json::from_str(...).unwrap()` or unchecked use of deserialized
    // values without validation. Semgrep rules will flag `from_str` + `unwrap` patterns.
    let parsed: HashMap<String, String> = serde_json::from_str(body).unwrap();
    // pretend we trust the parsed payload (insecure!)
    parsed
}

/// 5) Unsafe block example (presence of `unsafe` is often flagged)
fn unsafe_demo() {
    // This demonstrates legitimate-ish use of `unsafe` that many linters/semgrep rules
    // will highlight for review.
    let boxed = Box::new(100u32);
    // take ownership into raw pointer
    let raw = Box::into_raw(boxed);
    unsafe {
        // reassign through raw pointer
        *raw = 200u32;
        // reconstruct the Box to free memory safely
        let boxed_again = Box::from_raw(raw);
        println!("After unsafe edit: {}", boxed_again);
        // boxed_again is dropped at end of scope
    }
}
