/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// This file contains examples of digest operations.
// Three cipher flows are demonstrated:
// EP11 single-part (ESP), PKCS#11 single-part (PSP), and PKCS#11 multi-part (PMP)
//
// Each test name has a suffix of ESP, PSP, or PMP denoting the cipher flow used in the test.
// Refer to the ciper flow diagram in README.md.
//
// The following digest mechanisms (in variable form) can be used for digest operations:
// ep11.CKM_SHA_1
// ep11.CKM_SHA224
// ep11.CKM_SHA256 -- used in all of the digest examples
// ep11.CKM_SHA384
// ep11.CKM_SHA512_224
// ep11.CKM_SHA512_256
// ep11.CKM_SHA512
// ep11.CKM_IBM_SHA512_224
// ep11.CKM_IBM_SHA512_256
// ep11.CKM_IBM_SHA3_224 -- only works with IBM Crypto Express CEX7 and CEX8 cards
// ep11.CKM_IBM_SHA3_256 -- only works with IBM Crypto Express CEX7 and CEX8 cards
// ep11.CKM_IBM_SHA3_384 -- only works with IBM Crypto Express CEX7 and CEX8 cards
// ep11.CKM_IBM_SHA3_512 -- only works with IBM Crypto Express CEX7 and CEX8 cards

// Example_digest_ESP calculates the digest of some plain text
// Flow: connect, digest EP11 single-part data
func Example_digest_ESP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	digestData := []byte("This is data that is longer than 64 bytes. This is the data that is longer than 64 bytes.")

	digestSingleRequest := &pb.DigestSingleRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA256},
		Data: digestData,
	}

	digestSingleResponse, err := cryptoClient.DigestSingle(context.Background(), digestSingleRequest)
	if err != nil {
		panic(fmt.Errorf("DigestSingle error: %s", err))
	} else {
		fmt.Printf("Digest data: %x\n", digestSingleResponse.Digest)
	}

	// Output:
	// Digest data: b036abead70a9739648ab94d556bf120494eab3a470b5ee12be559b9dbc8c408
}

// Example_digest_PSP calculates the digest of some plain text
// Flow: connect, digest PKCS #11 single-part data
func Example_digest_PSP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	digestData := []byte("This is data that is longer than 64 bytes. This is the data that is longer than 64 bytes.")

	digestInitRequest := &pb.DigestInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA256},
	}

	digestInitResponse, err := cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("DigestInit error: %s", err))
	}

	digestRequest := &pb.DigestRequest{
		State: digestInitResponse.State,
		Data:  digestData,
	}

	digestResponse, err := cryptoClient.Digest(context.Background(), digestRequest)
	if err != nil {
		panic(fmt.Errorf("Digest error: %s", err))
	} else {
		fmt.Printf("Digest data: %x\n", digestResponse.Digest)
	}

	// Output:
	// Digest data: b036abead70a9739648ab94d556bf120494eab3a470b5ee12be559b9dbc8c408
}

// Example_digest_PMP calculates the digest of some plain text
// Flow: connect, digest PKCS #11 multi-part data
func Example_digest_PMP() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	digestData := []byte("This is data that is longer than 64 bytes. This is the data that is longer than 64 bytes.")

	digestInitRequest := &pb.DigestInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA256},
	}

	digestInitResponse, err := cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("DigestInit error: %s", err))
	}

	digestUpdateRequest := &pb.DigestUpdateRequest{
		State: digestInitResponse.State,
		Data:  digestData[:64],
	}

	// DigestUpdate with a portion of the data used for the digest operation
	digestUpdateResponse, err := cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DigestUpdate error: %s", err))
	}

	digestUpdateRequest = &pb.DigestUpdateRequest{
		State: digestUpdateResponse.State,
		Data:  digestData[64:],
	}

	// DigestUpdate with the remaining data
	digestUpdateResponse, err = cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("DigestUpdate error: %s", err))
	}

	digestFinalRequestInfo := &pb.DigestFinalRequest{
		State: digestUpdateResponse.State,
	}

	// Perform DigestFinal to complete the digest operation
	digestFinalResponse, err := cryptoClient.DigestFinal(context.Background(), digestFinalRequestInfo)
	if err != nil {
		panic(fmt.Errorf("DigestFinal error: %s", err))
	} else {
		fmt.Printf("Digest data: %x\n", digestFinalResponse.Digest)
	}

	// Output:
	// Digest data: b036abead70a9739648ab94d556bf120494eab3a470b5ee12be559b9dbc8c408
}
