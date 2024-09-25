/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"fmt"

	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Example_generateRandomBytes demonstrates the GenerateRandom PKCS #11 function
// implemented by EP11. Internally, hardware-seeded entropy is passed through a
// FIPS-compliant DRNG.
// Flow: connect, generate 4096 bytes of random data, confirm the length of the random data
func Example_generateRandomBytes() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	generateRandomRequest := &pb.GenerateRandomRequest{
		Len: (uint64)(4096), // Request 4K of random bytes
	}

	// Generate 4K of random bytes
	generateRandomResponse, err := cryptoClient.GenerateRandom(context.Background(), generateRandomRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}

	// Confirm that the length of the random bytes is 4096
	if len(generateRandomResponse.Rnd) != 4096 {
		panic(fmt.Errorf("Length of random bytes is not 4096 bytes"))
	}

	fmt.Println("Successfully generated 4096 bytes of random data")

	// Output:
	// Successfully generated 4096 bytes of random data
}
