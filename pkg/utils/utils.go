package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// NormalizePrefix converts an IP address with prefix length to its correct network ID
func NormalizePrefix(ipWithPrefix string) (string, error) {
	// Split IP and prefix length
	parts := strings.Split(ipWithPrefix, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid prefix format: %s", ipWithPrefix)
	}

	// Parse IP address
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", parts[0])
	}

	// Parse prefix length
	prefixLen, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid prefix length: %s", parts[1])
	}

	// Check if it's IPv4 or IPv6
	if ip.To4() != nil {
		// IPv4
		if prefixLen > 32 {
			return "", fmt.Errorf("invalid prefix length for IPv4: %d", prefixLen)
		}
		ip = ip.To4()
	} else {
		// IPv6
		if prefixLen > 128 {
			return "", fmt.Errorf("invalid prefix length for IPv6: %d", prefixLen)
		}
	}

	// Create IPNet
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(int(prefixLen), len(ip)*8),
	}

	// Get network address
	network := ipNet.IP.Mask(ipNet.Mask)

	return fmt.Sprintf("%s/%d", network.String(), prefixLen), nil
}
