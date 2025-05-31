package ripe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type Response struct {
	Data struct {
		ASNs   []string `json:"asns"`
		Prefix string   `json:"prefix"`
	} `json:"data"`
}

type RpkiResponse struct {
	Data struct {
		Status         string `json:"status"`
		ValidatingROAs []struct {
			Origin    string `json:"origin"`
			Prefix    string `json:"prefix"`
			MaxLength int    `json:"max_length"`
		} `json:"validating_roas"`
	} `json:"data"`
}

// GetCurrentPrefixInfoFromRipe retrieves prefix information from RIPE API
func GetCurrentPrefixInfoFromRipe(ip string) (uint32, []uint32, error) {
	// Construct the API URL
	url := fmt.Sprintf("https://stat.ripe.net/data/network-info/data.json?resource=%s", ip)
	fmt.Printf("[DEBUG] Calling RIPE Network Info API: %s\n", url)

	// Make the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to call RIPE API: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("RIPE API returned non-200 status: %d", resp.StatusCode)
	}

	// Parse the JSON response
	var ripeResp Response
	if err := json.NewDecoder(resp.Body).Decode(&ripeResp); err != nil {
		return 0, nil, fmt.Errorf("failed to parse RIPE API response: %v", err)
	}

	// Print the ASNs and prefix
	fmt.Printf("[DEBUG] Current DFZ: %s with origin %s\n", ripeResp.Data.Prefix, ripeResp.Data.ASNs)

	// Extract prefix length from the prefix string (e.g., "103.147.22.0/24" -> 24)
	parts := strings.Split(ripeResp.Data.Prefix, "/")
	if len(parts) != 2 {
		return 0, nil, fmt.Errorf("invalid prefix format: %s", ripeResp.Data.Prefix)
	}

	prefixLen, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid prefix length: %s", parts[1])
	}

	// Parse all ASNs from the list
	var asns []uint32
	for _, asnStr := range ripeResp.Data.ASNs {
		asnNum, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid ASN format: %s", asnStr)
		}
		asns = append(asns, uint32(asnNum))
	}
	fmt.Printf("[DEBUG] Parsed ASNs: %v\n", asns)

	return uint32(prefixLen), asns, nil
}

// GetCurrentRpkiInfoFromRipe retrieves RPKI validation information from RIPE API
func GetCurrentRpkiInfoFromRipe(prefix string, asn uint32) (uint32, uint32, error) {
	// Construct the API URL
	url := fmt.Sprintf("https://stat.ripe.net/data/rpki-validation/data.json?resource=%d&prefix=%s", asn, prefix)
	fmt.Printf("[DEBUG] Calling RIPE RPKI Validation API: %s\n", url)

	// Make the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to call RIPE API: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("RIPE API returned non-200 status: %d", resp.StatusCode)
	}

	// Parse the JSON response
	var ripeResp RpkiResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripeResp); err != nil {
		return 0, 0, fmt.Errorf("failed to parse RIPE API response: %v", err)
	}

	// Print RPKI validation information
	fmt.Printf("[DEBUG] RPKI Validation Response - Status: %s\n", ripeResp.Data.Status)

	// Find the maximum prefix length from valid ROAs
	var maxLength uint32
	var maxOrigin uint32
	if len(ripeResp.Data.ValidatingROAs) > 0 {
		fmt.Println("[DEBUG] Validating ROAs:")
		for _, roa := range ripeResp.Data.ValidatingROAs {
			fmt.Printf("[DEBUG]   Origin: %s, Prefix: %s, Max Length: %d\n",
				roa.Origin, roa.Prefix, roa.MaxLength)

			// Update maxLength if this ROA is valid and has a larger max length
			if uint32(roa.MaxLength) > maxLength {
				maxLength = uint32(roa.MaxLength)
				originNum, err := strconv.ParseUint(roa.Origin, 10, 32)
				if err != nil {
					return 0, 0, fmt.Errorf("invalid origin ASN: %s", roa.Origin)
				}
				maxOrigin = uint32(originNum)
			}
		}
	} else {
		fmt.Println("[DEBUG] No validating ROAs found")
	}

	return maxLength, maxOrigin, nil
}
