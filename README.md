# CryoJS

[![Build](https://github.com/SayR1n/CryoJS/actions/workflows/build.yml/badge.svg)](https://github.com/SayR1n/CryoJS/actions/workflows/build.yml)

A lightweight JavaScript runtime built in C++ using [Duktape](https://duktape.org) as the embedded engine. Run plain `.js` files or pack your entire project into an encrypted `.resource` archive that only CryoJS can execute.

---

## Features

- Execute `.js` files directly from the command line
- CommonJS `require()` with Node.js-style module resolution
- Automatic `.js` extension and `index.js` directory fallback
- Module cache — each file is loaded once per run
- `module.exports` replacement support
- `console.log`, `console.info`, `console.error`, `console.warn`
- `__filename` and `__dirname` available in every module
- Full stack traces on runtime errors
- **Pack your JS project into a single encrypted `.resource` file**
- AES-256-CBC encryption with a custom KDF (100 000 rounds)
- **DEFLATE compression** before encryption (miniz)
- `--include` glob patterns — pack JSON, text and other assets alongside JS
- `.cryopackignore` file to exclude files and directories
- XOR obfuscation on top of encryption — no readable strings in the binary
- Random salt and IV on every pack — same source produces different output each time
- Wrong password detection via embedded checksum
- Format is unrecognizable to tools like 7-Zip or WinRAR

---

## Requirements

- CMake 3.16+
- C++17 compiler (MSVC 2019+, GCC 9+, Clang 10+)

---

## Build

```bash
cmake -S . -B build
cmake --build build
```

Outputs:
- `build/Debug/CryoJS` — the JS runtime
- `build/Debug/cryopack` — the archive packer

---

## Usage

```bash
CryoJS -h | --help        Show help
CryoJS --version          Show version
```

### Run a plain JS file

```bash
CryoJS script.js
```

### Pack a JS project into a resource archive

```bash
cryopack <input_dir> <output.resource> <password> [options]
```

The file at `./main.js` (relative to the input directory) is used as the entry point by default.

```bash
cryopack ./myapp app.resource mySecretPassword
```

**Options:**

- `--include, -i <pattern>` — extra file glob to pack; repeatable. Default: `*.js`
- `-h, --help` — show help

Patterns support `*` and `?` (case-insensitive):

```bash
# pack JS files plus JSON configs and .txt assets
cryopack ./myapp app.resource p4ss --include "*.json" --include "*.txt"
```

A `.cryopackignore` file in the input directory excludes matching files and directories (`#` starts a comment):

```
build/
*.txt
secrets*
```

The payload is DEFLATE-compressed before encryption when that makes it smaller.

### Run a resource archive

```bash
CryoJS <archive.resource> <password> [entry_point]
```

`entry_point` defaults to `./main.js` if omitted.

```bash
CryoJS app.resource mySecretPassword
CryoJS app.resource mySecretPassword ./src/index.js
```

---

## Example

**Project layout:**

```
myapp/
├── main.js
└── math/
    ├── add.js
    └── multiply.js
```

**main.js:**

```js
var math = require('./math/multiply');
var add  = require('./math/add');

console.log('3 + 7 =', add.add(3, 7));
console.log('6 * 7 =', math.multiply(6, 7));
```

**Run directly:**

```bash
CryoJS myapp/main.js
```

**Pack and run encrypted:**

```bash
cryopack myapp/ myapp.resource p4ssw0rd
CryoJS myapp.resource p4ssw0rd
```

Output:

```
3 + 7 = 10
6 * 7 = 42
```

---

## Resource Format

The `.resource` format is a custom binary format — not a zip, tar, or any standard archive. 7-Zip, WinRAR, and similar tools cannot open it.

**Format v2 (current):**

```
[4  bytes]  Magic header (v2)
[1  byte ]  Format version
[1  byte ]  Flags (bit 0: payload compressed)
[10 bytes]  Random padding
[4  bytes]  XOR-obfuscated file count
[32 bytes]  Salt (random per pack)
[16 bytes]  AES IV (random per pack)
[4  bytes]  Encrypted payload size
[N  bytes]  AES-256-CBC encrypted payload
```

Everything after the first 4 magic bytes is XOR-obfuscated with the magic value, so no plaintext strings appear in the file.

The encrypted payload contains:
- If compressed: original payload size (32-bit LE), followed by the DEFLATE stream
- File count
- For each file: name length, name, data length, data
- A 32-bit checksum used to verify the password on load

Archives produced by CryoJS 1.0 (**format v1**, no version/flags bytes) are still readable.

**Key derivation** uses a custom 100 000-round mixing function over the password and salt — no external KDF library required.

---

## Project Structure

```
CryoJS/
├── CMakeLists.txt
├── src/
│   ├── main.cpp            — CryoJS runtime
│   ├── cryopack.cpp        — archive packer
│   └── resource_format.h   — shared format constants, KDF and glob matching
├── third_party/
│   ├── duktape/            — Duktape JS engine (v2.7.0)
│   ├── tiny-aes/           — tiny-AES-c (AES-256-CBC)
│   └── miniz/              — miniz (DEFLATE compression)
└── examples/
    ├── main.js
    └── math/
        ├── add.js
        └── multiply.js
```

---

## License

MIT — see [LICENSE](LICENSE)
