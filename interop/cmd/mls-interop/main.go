// Command mls-interop runs the MLSClient gRPC server for interoperability
// testing against the mlswg/mls-implementations test runner, OpenMLS, mls-rs,
// and other RFC 9420 implementations.
//
// Usage:
//
//	mls-interop [-port :50051]
//
// The server advertises ciphersuites 0x0001 (X25519_AES128GCM_SHA256_Ed25519)
// and 0x0002 (P256_AES128GCM_SHA256_P256).  Ciphersuite 0xF001 (X-Wing) is
// intentionally omitted from SupportedCiphersuites because it is a private-use
// suite that other stacks do not implement; it is exercised only in the
// self-conformance test.
package main

import (
	"flag"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/trevex/mls-go/interop/proto/mlspb"
	"github.com/trevex/mls-go/interop/server"
)

func main() {
	port := flag.String("port", ":50051", "TCP address to listen on (host:port)")
	flag.Parse()

	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("listen %s: %v", *port, err)
	}
	s := grpc.NewServer()
	pb.RegisterMLSClientServer(s, server.New())
	log.Printf("mls-interop MLSClient serving on %s", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
