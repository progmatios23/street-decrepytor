# Street-decrepytor

Private archive of the **important** Street trees (Python v1/v2 + Rust debugger).

Repo: https://github.com/progmatios23/street-decrepytor

**Start:** [VERSIONS.md](VERSIONS.md) · **honesty:** [v1/CRITICAL.md](v1/CRITICAL.md)

```
street-decrepytor/
├── v1/        Python pipeline (classify, dump RAM, recrack Potassium)
├── v2/        entropy / harvest / Unicorn / StreetKernel.c stub
├── rs/        native debugger + kernel RPM crate
└── java-sf/   SFsociety JAR/ZKM decrypt + Sydney 26.0 Fabric docs
```

Java / Fabric: [java-sf/README.md](java-sf/README.md).

No sample EXEs. No harvest blobs. No `rework/` dump.

## v1

```bash
cd v1
pip install -r requirements.txt
pip install -e .
python -m street_decrepytor classify some.exe
python -m unittest tests.test_honesty tests.test_classify -v
```

## v2

```bash
cd v2
pip install -e .
python -m street_v2 --help
```

## rs

```bash
cd rs
cargo test --workspace
cargo build --release
```
