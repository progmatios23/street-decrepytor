fn main() {
    if let Err(e) = street_mcp::serve_stdio() {
        eprintln!("street-mcp: {e}");
        std::process::exit(1);
    }
}
