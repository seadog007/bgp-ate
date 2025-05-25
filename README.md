# BGP-ATE

A tool for BGP route manipulation and certificate generation.

## Features

- BGP route manipulation
- Certificate generation with various 
- IP helper route management
- Support for both standard and large communities
- External Account Binding (EAB) support

## Prerequisites

- Go 1.21 or later
- GoBGP v3.37.0 or later

## Installation

1. Install GoBGP:
```bash
# Make the setup script executable
chmod +x setup.sh

# Run the setup script
./setup.sh

# Add gobgpbin to your PATH (optional)
export PATH="$(pwd)/gobgpbin:$PATH"
```

2. Install the BGP control system:
```bash
go build
```

## Usage

1. Start the GoBGP daemon:
```bash
sudo gobgpbin/gobgpd -f gobgpd.conf
```
2. Run the control system:
```bash
./bgpaite
```

## Configuration

The system uses `gobgpd.conf` for GoBGP configuration and `config.json` file for configuration. Here's an example:

```json
{
    "communities": ["large:18041:999:2"],
    "time": 10,
    "timeBeforeGeneratingCertificate": 5,
    "iphelperGateway": "192.168.99.1",
    "caDirUrl": "https://acme-v02.api.letsencrypt.org/directory",
    "eabKid": "",
    "eabHmacKey": ""
}
```

### Configuration Options

- `communities`: List of BGP communities (standard or large format)
  - Standard format: `"AS:value"` (e.g., `"65000:123"`)
  - Large format: `"large:AS:value1:value2"` (e.g., `"large:18041:999:2"`)
- `time`: Time in seconds to wait after hijacking
- `timeBeforeGeneratingCertificate`: Time in seconds to wait before generating certificate
- `iphelperGateway`: Gateway IP for iphelper command (optional, will use interface's default gateway if not specified)
- `caDirUrl`: ACME CA directory URL (optional, defaults to Let's Encrypt production)
- `eabKid`: External Account Binding Key ID (optional)
- `eabHmacKey`: External Account Binding HMAC Key (optional)

### CA Directory URLs

The `caDirUrl` field supports different ACME CA servers:

1. Let's Encrypt Production:
```json
"caDirUrl": "https://acme-v02.api.letsencrypt.org/directory"
```

2. Buypass:
```json
"caDirUrl": "https://api.buypass.com/acme/directory"
```

3. Google Public CA
```json
"caDirUrl": "https://dv.acme-v02.api.pki.goog/directory"
```
use `gcloud publicca external-account-keys create` to generate eabKid & eabHmacKey.

4. ZeroSSL
```json
"caDirUrl": "https://acme.zerossl.com/v2/DV90"
```

If `caDirUrl` is not specified, the tool will use Let's Encrypt's production server by default.

## Usage

### Building
```bash
go build
```

### Clear Routes
```bash
./bgpate clear
```

### Hijack Routes
```bash
./bgpate hijack <ip> [--dryrun]
```

### Generate Certificate
```bash
./bgpate certgen <domain> [--dryrun]
```

### IP Helper
```bash
./bgpate iphelper <ip> [-d]
```

## Full BGP Hijack Attack Procedures

1. Run 
```bash
./bgpate iphelper <ip>
```

2. 
```bash
./bgpate hijack <ip>
```

3. Run curl to confirm the hijacking is success
```
curl --interface <ip> https://1.1.1.1/cdn-cgi/trace
```

4. Remove IP configuration on the system
```bash
./bgpate iphelper <ip> -d
```

## Full Certification Generating Attack Procedures
TBD

## Notes

- The tool will automatically clean up routes when interrupted (Ctrl+C)
- For certificate generation, make sure port 80 is available for HTTP-01 challenge
- When using EAB, both `eabKid` and `eabHmacKey` must be provided

