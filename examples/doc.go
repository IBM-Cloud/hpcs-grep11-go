// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
Package examples contains sample code that uses the GREP11 API
to communicate with an IBM Cloud HPCS instance.

At a high level GREP11 function calls to an HPCS instance consist of the following steps:

	1. Connect to the HPCS server instance
	2. Create a crypto client instance
	3. Create a GREP11 gRPC request message
	4. Send the gRPC request message to the HPCS server instance
	5. Receive the gRPC response from the HPCS server instance and check if an error occured

For more information about the GREP11 API, please visit https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-grep11-api-ref

Key Templates

For key operations (GenerateKey, GenerateKeyPair, DeriveKey, WrapKey, UnwrapKey), you will be required to
supply key attributes.  The attributes will vary depending on the type of key operation being performed.
Helper functions and a helper type have been provided to configure and properly format attributes associated with keys.

The following code snippet shows how to use the helper functions and helper type for generating an RSA key pair.

	publicExponent := []byte{0x11}
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_VERIFY:          true,
		ep11.CKA_MODULUS_BITS:    2048,
		ep11.CKA_PUBLIC_EXPONENT: publicExponent,
		ep11.CKA_EXTRACTABLE:     false,
	}
	privateKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_PRIVATE:     true,
		ep11.CKA_SENSITIVE:   true,
		ep11.CKA_DECRYPT:     true,
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
	}
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyTemplate),
	}

The ep11.EP11Attributes type is a map containing PKCS11 constants and their values.

The util.AttributeMap helper function converts the EP11Attributes map into a protobuf format suitable for
transporting via gRPC.


Error Messages

The helper function, util.Convert(), can be used to extract information from the returned gRPC error data structure.
The Grep11Error data structure consists of a return code field whose value correlates with a standard PKCS11 error code.  The
error codes can be found in the ep11/header_consts.go file.  In addition to the return code, there may be additional information
contained in the Details field of the Grep11Error data structure.

The following code snippet shows how the util.Convert() function is used to check for errors after a verify operation:

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}



IBM Cloud Identity Access and Management (IAM) Bearer Tokens

Helper functions and a helper data type (IAMPerRPCCredentials) are provided to request and manage bearer tokens obtained from the IBM Cloud via IAM.
The tokens are incorporated into the gRPC credentials call option during the initial connection (gRPC Dial) through the
use of the GetRequestMetadata and getToken helper functions contained in util/util.go.

The following code snippet shows how to setup IBM Cloud HPCS credentials:

	const address = "<grep11_server_address>:<port>"

	var callOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
			APIKey:   "<ibm_cloud_apikey>",
			Endpoint: "<https://<iam_ibm_cloud_endpoint>",
			Instance: "<hpcs_instance_id>",
		}),
	}

The instance address and port, APIKey, IAM endpoint, and the HPCS instance ID need to be specified. Update
the server_test.go file with the connection information prior to running the examples.


*/
package examples
