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

// Example_mechanism_List retrieves a list of supoorted mechanisms
// Flow: connect, get mechanism list
func Example_mechanism_List() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	mechanismListRequest := &pb.GetMechanismListRequest{}

	// Retrieve a list of all supported mechanisms
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Retrieved mechanism list:\n%v ...\n", mechanismListResponse.Mechs[:1])

	// Output:
	// Retrieved mechanism list:
	// [CKM_RSA_PKCS] ...
}

// Example_mechanism_Info retrieves retrieves detailed information for the CKM_RSA_PKCS mechanism
// Flow: connect, get mechanism info
func Example_mechanism_Info() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}

	// Retrieve information about the CKM_RSA_PKCS mechanism
	mechanismInfoResponse, err := cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}

	fmt.Println("Retrieved CKM_RSA_PKCS mechanism information")

	fmt.Printf("Minimum Key Size: %d\n", mechanismInfoResponse.MechInfo.MinKeySize)
	fmt.Printf("Maximum Key Size: %d\n", mechanismInfoResponse.MechInfo.MaxKeySize)

	// Output:
	// Retrieved CKM_RSA_PKCS mechanism information
	// Minimum Key Size: 512
	// Maximum Key Size: 4096
}
