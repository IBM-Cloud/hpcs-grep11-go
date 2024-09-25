/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"crypto/tls"
	"os"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/authorize"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	// ClientConfig contains required information to connect to a remote HPCS instance
	ClientConfig util.ClientConfig
)

// Obtain Address, APIKey, and IAMEndpoint environment variables if they are set.
// The Address and APIKey variables can be changed prior to running the sample program.
// Optionally, GREP11_ADDRESS, GREP11_APIKEY and GREP11_IAMENDPOINT environment variables can be set,
// overriding the current/default values of the ClientConfig fields: Address, APIKey and IAMEndpoint.
func init() {

	ClientConfig.Address = "<grep11_server_address>:<port>"
	ClientConfig.APIKey = "<ibm_cloud_apikey>"
	ClientConfig.IAMEndpoint = "https://iam.cloud.ibm.com"

	if address, exists := os.LookupEnv("GREP11_ADDRESS"); exists {
		ClientConfig.Address = address
	}
	if apiKey, exists := os.LookupEnv("GREP11_APIKEY"); exists {
		ClientConfig.APIKey = apiKey
	}
	if iamEndpoint, exists := os.LookupEnv("GREP11_IAMENDPOINT"); exists {
		ClientConfig.IAMEndpoint = iamEndpoint
	}

	ClientConfig.DialOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&authorize.IAMPerRPCCredentials{
			APIKey:   ClientConfig.APIKey,
			Endpoint: ClientConfig.IAMEndpoint,
		}),
	}

	if _, exists := os.LookupEnv("GREP11_LOCAL"); exists {
		ClientConfig.DialOpts = []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}
	}
}
