// Command headervector validates one official consensus-spec-tests
// BeaconBlockHeader vector (Fulu, mainnet): decompress snappy, deserialize via
// offchain/ssz, recompute hash_tree_root, compare to roots.yaml + value.yaml.
// Usage: go run ./cmd/headervector <dir>
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/snappy"
	"gopkg.in/yaml.v3"

	"eth-cardano-zk-light-client/prover/offchain/ssz"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: headervector <dir>")
		os.Exit(2)
	}
	vectorDir := os.Args[1]

	compressedVector := readFile(filepath.Join(vectorDir, "serialized.ssz_snappy"))
	if bytes.HasPrefix(compressedVector, []byte("version https://git-lfs")) {
		halt("serialized.ssz_snappy is a Git-LFS pointer — refetch via media.githubusercontent.com")
	}
	serializedHeader, err := snappy.Decode(nil, compressedVector) // consensus-spec-tests use block-format snappy
	if err != nil {
		serializedHeader, err = io.ReadAll(snappy.NewReader(bytes.NewReader(compressedVector)))
		check(err, "snappy decode (block then framed)")
	}
	header, err := ssz.Deserialize(serializedHeader)
	check(err, "ssz deserialize")

	valueYAML := readYAML(filepath.Join(vectorDir, "value.yaml"))
	rootsYAML := readYAML(filepath.Join(vectorDir, "roots.yaml"))
	officialRoot := mustHex(fmt.Sprintf("%v", rootsYAML["root"]))
	recomputedRoot := header.HashTreeRoot()

	fmt.Printf("slot                 : %d\n", header.Slot)
	fmt.Printf("proposer_index       : %d\n", header.ProposerIndex)
	fmt.Printf("parent_root          : 0x%x\n", header.ParentRoot)
	fmt.Printf("state_root           : 0x%x\n", header.StateRoot)
	fmt.Printf("body_root            : 0x%x\n", header.BodyRoot)
	fmt.Printf("recomputed htr       : 0x%x\n", recomputedRoot)
	fmt.Printf("official root (yaml) : 0x%s\n", hex.EncodeToString(officialRoot))

	fieldsMatch := fmt.Sprintf("%v", valueYAML["slot"]) == strconv.FormatUint(header.Slot, 10) &&
		fmt.Sprintf("%v", valueYAML["proposer_index"]) == strconv.FormatUint(header.ProposerIndex, 10) &&
		bytes.Equal(header.ParentRoot[:], mustHex(fmt.Sprintf("%v", valueYAML["parent_root"]))) &&
		bytes.Equal(header.StateRoot[:], mustHex(fmt.Sprintf("%v", valueYAML["state_root"]))) &&
		bytes.Equal(header.BodyRoot[:], mustHex(fmt.Sprintf("%v", valueYAML["body_root"])))
	rootMatches := bytes.Equal(recomputedRoot[:], officialRoot)
	fmt.Printf("\nfields match value.yaml : %v\nhtr == roots.yaml root  : %v\n", fieldsMatch, rootMatches)
	if !fieldsMatch || !rootMatches {
		halt(fmt.Sprintf("validation failed (fieldsMatch=%v rootMatches=%v)", fieldsMatch, rootMatches))
	}
	fmt.Println("\nPASS: official Fulu BeaconBlockHeader vector validated.")
}

func readFile(path string) []byte {
	contents, err := os.ReadFile(path)
	check(err, "read "+path)
	return contents
}
func readYAML(path string) map[string]any {
	fileBytes := readFile(path)
	if bytes.HasPrefix(fileBytes, []byte("version https://git-lfs")) {
		halt(path + " is a Git-LFS pointer, not data")
	}
	var parsedYAML map[string]any
	check(yaml.Unmarshal(fileBytes, &parsedYAML), "yaml "+path)
	return parsedYAML
}
func mustHex(hexString string) []byte {
	hexString = strings.TrimPrefix(strings.Trim(strings.TrimSpace(hexString), "'\""), "0x")
	decoded, err := hex.DecodeString(hexString)
	check(err, "hex "+hexString)
	return decoded
}
func check(err error, operation string) {
	if err != nil {
		halt(operation + ": " + err.Error())
	}
}
func halt(message string) { fmt.Fprintln(os.Stderr, "HALT: "+message); os.Exit(1) }
