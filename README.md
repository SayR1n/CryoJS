# CryoJS

A lightweight JavaScript runtime built in C++ using [Duktape](https://duktape.org) as the embedded engine. Run plain `.js` files or pack your entire project into an encrypted `.resource` archive that only CryoJS can execute.

---

## Features

- Execute `.js` files directly from the command line
- CommonJS `require()` with Node.js-style module resolution
- Automatic `.js` extension and `index.js` directory fallback
- Module cache — each file is loaded once per run
- `module.exports` replacement support
- `console.log`, `console.error`, `console.warn`
- `__filename` and `__dirname` available in every module
- Full stack traces on runtime errors
- **Pack your JS project into a single encrypted `.resource` file**
- AES-256-CBC encryption with a custom KDF (100 000 rounds)
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

### Run a plain JS file

```bash
CryoJS script.js
```

### Pack a JS project into a resource archive

```bash
cryopack <input_dir> <output.resource> <password>
```

`cryopack` recursively collects all `.js` files from `input_dir` and packs them into a single encrypted archive. The file at `./main.js` (relative to the input directory) is used as the entry point by default.

```bash
cryopack ./myapp app.resource mySecretPassword
```

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

```
[4  bytes]  Magic header
[12 bytes]  Random padding
[4  bytes]  XOR-obfuscated file count
[32 bytes]  Salt (random per pack)
[16 bytes]  AES IV (random per pack)
[4  bytes]  Encrypted payload size
[N  bytes]  AES-256-CBC encrypted payload
```

Everything after the first 4 magic bytes is XOR-obfuscated with the magic value, so no plaintext strings appear in the file.

The encrypted payload contains:
- File count
- For each file: name length, name, data length, data
- A 32-bit checksum used to verify the password on load

**Key derivation** uses a custom 100 000-round mixing function over the password and salt — no external KDF library required.

---

## Project Structure

```
CryoJS/
├── CMakeLists.txt
├── src/
│   ├── main.cpp            — CryoJS runtime
│   ├── cryopack.cpp        — archive packer
│   └── resource_format.h   — shared format constants and KDF
├── third_party/
│   ├── duktape/            — Duktape JS engine (v2.7.0)
│   └── tiny-aes/           — tiny-AES-c (AES-256-CBC)
└── examples/
    ├── main.js
    └── math/
        ├── add.js
        └── multiply.js
```

---

## License

MIT — see [LICENSE](LICENSE)
