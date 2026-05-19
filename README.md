# sigwatch

Static file analyzer for malware triage and IOC checking.

## Build

```bash
make build
```

## Usage

```bash
./bin/sigwatch sample.bin
./bin/sigwatch -o json sample.bin
./bin/sigwatch -ioc hashes.txt sample.bin
```

## Features

- MD5, SHA1, and SHA256 hashing
- Shannon entropy scoring
- PE, ELF, and Mach-O header detection
- Printable string extraction
- Regex signature rules
- Optional SHA256 IOC list matching

## License

MIT — see [LICENSE](LICENSE).
