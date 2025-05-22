# BGP Control System

A BGP control system built using GoBGP. This system provides a programmatic way to manage BGP sessions and routes.

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

The system uses `gobgpd.conf` for GoBGP configuration and `config.yaml` for the control system configuration.

