//! siwx-cli — Command-line tool for Sign-In with X message generation.

#[allow(clippy::print_stdout)]
fn main() {
    let msg = siwx::SiwxMessage::new(
        "example.com",
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "https://example.com/login",
        "1",
        "1",
    )
    .expect("valid message")
    .with_statement("Sign in to Example App")
    .with_nonce(siwx::nonce::generate_default());

    println!("=== Ethereum ===");
    println!("{}", siwx_evm::format_message(&msg));
    println!();

    let sol_msg = siwx::SiwxMessage::new(
        "example.com",
        "GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
        "https://example.com/login",
        "1",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    )
    .expect("valid message")
    .with_statement("Sign in to Example App")
    .with_nonce(siwx::nonce::generate_default());

    println!("=== Solana ===");
    println!("{}", siwx_svm::format_message(&sol_msg));
}
