//! Narrow, real boundaries: descriptor-pinned flat files and import-free Wasm.
//! Native programs, dynamic filesystem trees, sockets and arbitrary modules are unavailable.
use crate::Result;
#[cfg(unix)]
use rustix::fs::{open, openat, Mode, OFlags};
#[cfg(unix)]
use std::{
    fs::File,
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

#[cfg(unix)]
pub struct PinnedFiles {
    input: File,
    output: File,
}
#[cfg(unix)]
impl PinnedFiles {
    pub fn open(root: &Path) -> Result<Self> {
        let dir = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let pin = |name: &str, write: bool| -> Result<File> {
            let flags = if write { OFlags::RDWR } else { OFlags::RDONLY };
            let f = File::from(openat(
                &dir,
                name,
                flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            let meta = f.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > 32768 {
                return Err("unsafe file type".into());
            }
            Ok(f)
        };
        Ok(Self {
            input: pin("input.txt", false)?,
            output: pin("output.txt", true)?,
        })
    }
    pub fn read(&self, name: &str) -> Result<String> {
        let f = match name {
            "input.txt" => &self.input,
            "output.txt" => &self.output,
            _ => return Err("unknown pinned file".into()),
        };
        let mut data = vec![0; 32769];
        let size = f.read_at(&mut data, 0)?;
        if size > 32768 {
            return Err("file too large".into());
        }
        Ok(String::from_utf8(data[..size].to_vec())?)
    }
    pub fn write(&self, name: &str, body: &str) -> Result<()> {
        if name != "output.txt" || body.len() > 32768 {
            return Err("invalid pinned write".into());
        }
        self.output.write_all_at(body.as_bytes(), 0)?;
        self.output.set_len(body.len() as u64)?;
        self.output.sync_data()?;
        Ok(())
    }
}

// Native Windows filesystem capability deliberately unavailable. No path-based fallback.
#[cfg(not(unix))]
pub struct PinnedFiles;
#[cfg(not(unix))]
impl PinnedFiles {
    pub fn read(&self, _: &str) -> Result<String> {
        Err("native filesystem isolation unavailable".into())
    }
    pub fn write(&self, _: &str, _: &str) -> Result<()> {
        Err("native filesystem isolation unavailable".into())
    }
}

pub fn pinned_fixture() -> Result<Option<(tempfile::TempDir, PinnedFiles)>> {
    #[cfg(unix)]
    {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("input.txt"), "Synthetic isolated input")?;
        std::fs::write(root.path().join("output.txt"), "")?;
        let files = PinnedFiles::open(root.path())?;
        Ok(Some((root, files)))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

const CHECKSUM: &str = r#"(module
 (memory (export "memory") 1 1)
 (func (export "run") (param $n i32) (result i32) (local $i i32) (local $sum i32)
  (block $end (loop $loop
   (br_if $end (i32.ge_u (local.get $i) (local.get $n)))
   (local.set $sum (i32.add (local.get $sum) (i32.load8_u (local.get $i))))
   (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $loop)))
  (local.get $sum)))"#;

pub struct WasmTool {
    engine: Engine,
    module: Module,
}
impl WasmTool {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(65536);
        let engine = Engine::new(&config)?;
        let module = Module::new(&engine, CHECKSUM)?;
        Ok(Self { engine, module })
    }
    fn store(&self) -> Result<Store<StoreLimits>> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(65536)
            .table_elements(0)
            .instances(1)
            .memories(1)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|s| s);
        store.set_fuel(2_000_000)?;
        store.set_epoch_deadline(1);
        Ok(store)
    }
    pub fn run(&self, body: &str) -> Result<String> {
        if body.len() > 32768 {
            return Err("input too large".into());
        }
        let mut store = self.store()?;
        // No imports at all: no WASI filesystem, network, environment or host calls.
        let instance = Instance::new(&mut store, &self.module, &[])?;
        instance
            .get_memory(&mut store, "memory")
            .ok_or("missing memory")?
            .write(&mut store, 0, body.as_bytes())?;
        let engine = self.engine.clone();
        let (cancel, receiver) = std::sync::mpsc::channel();
        let timer = std::thread::spawn(move || {
            if receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
            {
                engine.increment_epoch();
            }
        });
        let run = instance.get_typed_func::<i32, i32>(&mut store, "run")?;
        let result = run.call(&mut store, body.len() as i32);
        let _ = cancel.send(());
        let _ = timer.join();
        Ok(format!("checksum:{}", result?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input.txt"), "synthetic").unwrap();
        std::fs::write(root.path().join("output.txt"), "").unwrap();
        root
    }
    #[test]
    #[cfg(unix)]
    fn pins_survive_symlink_and_directory_replacement() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("input.txt"), "safe").unwrap();
        std::fs::write(root.join("output.txt"), "").unwrap();
        let files = PinnedFiles::open(&root).unwrap();
        let outside = outer.path().join("outside");
        std::fs::write(&outside, "unchanged").unwrap();
        std::fs::rename(&root, outer.path().join("moved")).unwrap();
        std::fs::create_dir(&root).unwrap();
        symlink(&outside, root.join("output.txt")).unwrap();
        files.write("output.txt", "safe output").unwrap();
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "unchanged");
        assert_eq!(files.read("input.txt").unwrap(), "safe");
        assert_eq!(
            std::fs::read_to_string(outer.path().join("moved/output.txt")).unwrap(),
            "safe output"
        );
    }
    #[test]
    #[cfg(unix)]
    fn rejects_links_and_unknown_creation() {
        let root = fixture();
        std::fs::remove_file(root.path().join("input.txt")).unwrap();
        symlink("output.txt", root.path().join("input.txt")).unwrap();
        assert!(PinnedFiles::open(root.path()).is_err());
        std::fs::remove_file(root.path().join("input.txt")).unwrap();
        std::fs::hard_link(
            root.path().join("output.txt"),
            root.path().join("input.txt"),
        )
        .unwrap();
        assert!(PinnedFiles::open(root.path()).is_err());
        let other = fixture();
        let files = PinnedFiles::open(other.path()).unwrap();
        assert!(files.write("new.txt", "x").is_err());
        assert!(files.read("../x").is_err());
    }
    #[test]
    #[cfg(unix)]
    fn concurrent_leaf_substitution_cannot_redirect_pinned_write() {
        let root = fixture();
        let files = PinnedFiles::open(root.path()).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, "untouched").unwrap();
        let path = root.path().join("output.txt");
        let dest = outside.clone();
        let attacker = std::thread::spawn(move || {
            for _ in 0..300 {
                let _ = std::fs::remove_file(&path);
                let _ = symlink(&dest, &path);
            }
        });
        for _ in 0..300 {
            files.write("output.txt", "pinned").unwrap();
        }
        attacker.join().unwrap();
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "untouched");
    }
    #[test]
    #[cfg(windows)]
    fn native_files_are_unavailable() {
        assert!(pinned_fixture().unwrap().is_none());
        assert!(PinnedFiles.read("input.txt").is_err());
        assert!(PinnedFiles.write("output.txt", "x").is_err());
    }

    #[test]
    fn wasm_output_and_import_denial() {
        let tool = WasmTool::new().unwrap();
        assert_eq!(tool.run("ABC").unwrap(), "checksum:198");
        for namespace in ["wasi_snapshot_preview1", "wasi:sockets", "host_environment"] {
            let module = Module::new(
                &tool.engine,
                format!(r#"(module (import "{namespace}" "escape" (func)))"#),
            )
            .unwrap();
            assert!(Instance::new(&mut tool.store().unwrap(), &module, &[]).is_err());
        }
    }
    #[test]
    fn wasm_fuel_and_memory_limits() {
        let tool = WasmTool::new().unwrap();
        let mut store = tool.store().unwrap();
        store.set_fuel(1000).unwrap();
        let module = Module::new(
            &tool.engine,
            r#"(module (func (export "run") (loop $l (br $l))))"#,
        )
        .unwrap();
        let instance = Instance::new(&mut store, &module, &[]).unwrap();
        assert!(instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .unwrap()
            .call(&mut store, ())
            .is_err());
        let module = Module::new(&tool.engine, "(module (memory 2))").unwrap();
        assert!(Instance::new(&mut tool.store().unwrap(), &module, &[]).is_err());
    }
}
