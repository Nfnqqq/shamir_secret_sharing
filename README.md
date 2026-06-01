# Shamir Secret Sharing (SSSS)

A simple command-line tool to split secrets (like cryptocurrency seed phrases) into multiple shares using Shamir's Secret Sharing scheme. Any threshold number of shares can reconstruct the original secret, but fewer shares reveal nothing.

https://medium.com/starbugs/introduction-to-shamirs-secret-sharing-adf713e6430d    --- ssss
https://medium.com/airgap-it/airgap-the-step-by-step-guide-bff36d50a4ed  ---- airgap setup

## How It Works

- Split a secret into `n` shares
- Require any `t` shares to reconstruct (threshold)
- Fewer than `t` shares reveal **zero information** about the secret

Example: Split into 3 shares, require 2 to recover. You can lose 1 share and still recover your secret.

## Output Format

Shares are output as **decimal digits** grouped in 5s for easy handwriting:

```
┌────────────────────────────────────────┐
│ SHARE 1 of 3              (need 2)  │
├────────────────────────────────────────┤
│ 84771 21625 04410 59145 75476 63662  │
│ 89515 43022 32644 79108 83091 94487  │
│ ...                                    │
├────────────────────────────────────────┤
│ Checksum: 42                          │
└────────────────────────────────────────┘
```

- **Index**: Share number (1, 2, 3...)
- **Value**: The grouped digits
- **Checksum**: Sum of all digits mod 97 (for verification)

## Usage

### Split a Secret

```bash
ssss-split -t <threshold> -n <num_shares>
```

**Example**: Create 3 shares, require 2 to recover:
```bash
ssss-split -t 2 -n 3
Enter secret: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

### Combine Shares

```bash
ssss-combine -t <threshold>
```

**Example**: Recover using 2 shares:
```bash
ssss-combine -t 2
Share 1 of 2:
  Index: 1
  Value: 84771 21625 04410 59145 75476 63662 ...

Share 2 of 2:
  Index: 3
  Value: 56514 14416 69607 06097 16984 42441 ...

Recovered secret: abandon abandon abandon abandon ...
```

**Note**: Value must be entered as **one line**. Spaces are OK.

## How to Distribute Shares

### For a 2-of-3 Setup

Store each share in a **different physical location**:

| Share | Location Example |
|-------|------------------|
| Share 1 | Home safe |
| Share 2 | Bank safety deposit box |
| Share 3 | Trusted family member |

### Security Guidelines

- **Never** store all shares together
- **Never** store shares digitally (no photos, no cloud storage)
- Write on durable material (metal plates for fire resistance)
- Each share should include:
  - Share index (1, 2, or 3)
  - The value (all digit groups)
  - Checksum (for verification)
  - Note: "Need 2 of 3 shares to recover"

### What to Write on Paper

```
SHARE 2 of 3 (need 2 to recover)

INDEX: 2

VALUE:
56514 14416 69607 06097 16984 42441
93010 28681 55096 52739 22061 29658
42315 72825 59086 16315 53266 33474
[... continue all groups ...]

CHECKSUM: 75
```

## Installation

### macOS

**Prerequisites**: Install GMP library
```bash
brew install gmp
```

**Build and Install**:
```bash
cd shamir_secret_sharing
make clean && make
sudo cp ./ssss /usr/local/bin/ssss
sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-split
sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-combine
```

**Verify**:
```bash
ssss-split -t 2 -n 3
```

### Windows

**Option 1: WSL (Windows Subsystem for Linux)**

1. Install WSL: Open PowerShell as Admin and run:
   ```powershell
   wsl --install
   ```

2. Open WSL terminal and install dependencies:
   ```bash
   sudo apt update
   sudo apt install build-essential libgmp-dev
   ```

3. Build:
   ```bash
   cd /path/to/shamir_secret_sharing
   make clean && make
   sudo cp ./ssss /usr/local/bin/
   sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-split
   sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-combine
   ```

**Option 2: Native Windows (MinGW-w64)**

1. Install MSYS2 from https://www.msys2.org/

2. Open MSYS2 terminal and install dependencies:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gmp make
   ```

3. Build:
   ```bash
   cd /path/to/shamir_secret_sharing
   make clean && make
   ```

4. Copy `ssss.exe` to a directory in your PATH.

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install build-essential libgmp-dev

cd shamir_secret_sharing
make clean && make
sudo cp ./ssss /usr/local/bin/
sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-split
sudo ln -sf /usr/local/bin/ssss /usr/local/bin/ssss-combine
```

## Security Best Practices

### When Splitting

1. **Disconnect from network** before running
   ```bash
   # macOS
   networksetup -setairportpower en0 off
   ```

2. **Disable shell history**
   ```bash
   unset HISTFILE
   ```

3. **Clear terminal after**
   ```bash
   clear && printf '\e[3J'
   ```

4. **Clear clipboard**
   ```bash
   # macOS
   pbcopy < /dev/null

   # Linux
   xclip -selection clipboard < /dev/null
   ```

### When Combining

- Use an air-gapped computer if possible
- Boot from a live USB (like Tails OS) for maximum security
- Never enter shares on a compromised machine

## Technical Details

- Uses a fixed 1536-bit prime for all operations
- Polynomial evaluation over finite field GF(p)
- Random coefficients generated from `/dev/urandom`
- Lagrange interpolation for reconstruction

## Common Schemes

| Scheme | Use Case |
|--------|----------|
| 2-of-3 | Personal backup, lose 1 share OK |
| 3-of-5 | Family/business, more redundancy |
| 2-of-2 | Two-party control, both required |

## Troubleshooting

**"Error combining shares"**
- Check that share indices match what was generated
- Verify all digits were copied correctly
- Use checksum to verify each share

**Value too long to type**
- Paste the entire value as one line
- Spaces are allowed, line breaks are not

## License

MIT License
