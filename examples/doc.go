// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
Package examples contains sample code that uses the GREP11 API
to communicate with an IBM Cloud HPCS instance.

At a high level, a GREP11 function call to an HPCS server instance consists of the following steps:

	1. Connect to the HPCS server instance
	2. Create a crypto client instance
	3. Create a GREP11 gRPC request message
	4. Send the gRPC request message to the HPCS server instance
	5. Receive the gRPC response from the HPCS server instance and check if an error occured

GREP11 is derived from Enterprise PKCS #11 (EP11) over gRPC, and since this API is based on the PKCS #11 specification,
all API input messages (protobuf messages) have a Mechanism field that must be specified.  A mechanism is
a value that determines what cryptographic operation is to be performed. Some cryptographic operations require
a mechanism parameter such as an initialization vector for encrypt operations using an AES key. A helper function,
util.SetMechParm, is provided to reduce the code clutter when setting your mechanism parameter within your
gRPC input (request) messages.

The GREP11 API is contained within the protobuf source file protos/server.proto and describes the Crypto service,
its methods, and the input and output (request and response) messages. For more information about the GREP11 API,
please visit https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-grep11-api-ref

As described in the hpcs-grep11-go README.md file, there are three different types of ciper flows each consisting
of a set of sub-operations that can be used for most GREP11 operations.
For example, the Encrypt operation consists of EncryptInit(), Encrypt(),
EncryptUpdate(), EncryptFinal() and EncryptSingle() sub-operations.

GREP11 sub-operations for Encrypt:
- EncryptInit() is used to initialize an operation and must be run prior to Encrypt(), EncryptUpdate(), or EncryptFinal() calls

- Encrypt() is used to encrypt data without the need to perform EncryptUpdate() or EncryptFinal() sub-operations

- EncryptUpdate() is used to perform update operations as part of a multi-part operation

- EncryptFinal() is used to perform final operations as part of a multi-part operation

- EncryptSingle() is an IBM EP11 extension to the standard PKCS#11 specification and used to perform a single call
without the need to use the Init, Update, and Final sub-operations

	Cipher Flow 1:
	EncryptInit(), Encrypt()

	Ciper Flow 2:
	EncryptInit(), EncryptUpdate(), EncryptUpdate()..., EncryptFinal()

	Ciper Flow 3:
	EncryptSingle()

Key Templates

For key operations (GenerateKey, GenerateKeyPair, DeriveKey, WrapKey, UnwrapKey), you will be required to
supply key attributes.  The attributes will vary depending on the type of key operation being performed.
Helper functions and a helper type have been provided to configure and properly format attributes associated with keys.

The following code snippet shows how to use the helper functions and helper type for generating an RSA key pair.

	publicExponent := 17
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
	}



IBM Cloud Identity Access and Management (IAM) Bearer Tokens

Helper functions and a helper data type (IAMPerRPCCredentials) are provided to request and manage bearer tokens obtained from the IBM Cloud via IAM.
The tokens are incorporated into the gRPC credentials call option during the initial connection (gRPC Dial) through the
use of the GetRequestMetadata and getToken helper functions contained in util/util.go.

The following code snippet shows how to setup IBM Cloud HPCS credentials:

	var (
		address        = "<grep11_server_address>:<port>"
		apiKey         = "<ibm_cloud_apikey>"
		hpcsInstanceID = "<hpcs_instance_id>"
	)

	var callOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
			APIKey:   apiKey,
			Instance: hpcsInstanceID,
			Endpoint: "https://iam.cloud.ibm.com",
		}),
	}

The instance address and port, APIKey, and the HPCS instance ID need to be specified. Update
the server_test.go file with the connection information prior to running the examples.


*/
package examples
