// Package proto hosts the vendored mls_client.proto and the //go:generate
// directive for regenerating the mlspb stubs. Regenerate with `just gen`.
package proto

//go:generate protoc --proto_path=. --go_out=mlspb --go_opt=paths=source_relative --go-grpc_out=mlspb --go-grpc_opt=paths=source_relative mls_client.proto
