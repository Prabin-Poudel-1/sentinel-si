//! One trusted bootstrap frame, then bounded untrusted JSON-line requests.
use sentinel_runtime::{now, Bootstrap, Engine, Result, ToolRequest};
use std::io::{self, BufRead, Read, Write};

fn frame(input: &mut impl BufRead, max: usize) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let n = input.take((max + 1) as u64).read_until(b'\n', &mut bytes)?;
    if n == 0 {
        return Ok(None);
    }
    if n > max || bytes.last() != Some(&b'\n') {
        return Err("invalid frame".into());
    }
    Ok(Some(bytes))
}
fn run() -> Result<()> {
    let path = std::env::args().nth(1).ok_or("audit path required")?;
    let mut input = io::stdin().lock();
    let boot: Bootstrap =
        serde_json::from_slice(&frame(&mut input, 5_000_000)?.ok_or("bootstrap required")?)?;
    let db = rusqlite::Connection::open(path)?;
    let mut engine = Engine::new(boot, db, now()?)?;
    let mut output = io::stdout().lock();
    writeln!(output, "{{\"ready\":true}}")?;
    output.flush()?;
    for _ in 0..10_000 {
        let bytes = match frame(&mut input, 65_536) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(()),
            Err(_) => {
                engine.malformed(now()?)?;
                return Err("invalid frame".into());
            }
        };
        let response = match serde_json::from_slice::<ToolRequest>(&bytes) {
            Ok(req) => engine.execute(req)?,
            Err(_) => engine.malformed(now()?)?,
        };
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
        output.flush()?;
    }
    Err("request limit".into())
}
fn main() {
    if run().is_err() {
        // Never print parser/database errors: they can contain confidential input.
        eprintln!("sentinel-runtime: failed closed");
        std::process::exit(1);
    }
}
