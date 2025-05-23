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

	// Convert IP to 4-byte representation
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", parts[0])
	}

	// Create IPNet
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(int(prefixLen), 32),
	}

	// Get network address
	network := ipNet.IP.Mask(ipNet.Mask)

	return fmt.Sprintf("%s/%d", network.String(), prefixLen), nil
} 