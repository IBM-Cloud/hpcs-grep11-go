// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
Package "examples" contains sample code that uses the GREP11 API to communicate with
an IBM Cloud Hyperprotect Crypto Services (HPCS) instance. The HPCS instance is configured
with a Hardware Security Module (HSM) using an IBM Crypto Express card.

The examples consist of the following major categories:
- Key generation
- Encrypt and decrypt
- Sign and verify
- Wrap and unwrap
- Key derivation
- Digest
- Mechanism information
- Generating random data

In addition there are examples that demonstrate the use of BIP32, SLIP10, BLS12-381, Kyber,
Dilithium, Schnorr, and Edwards Curve. Depending on what type of IBM Crypto Expresss card is
being used for your HPCS instance, the example code may skip tests. This is documented in the
example code.

At a high level, a GREP11 function call to an HPCS server instance consists of the following steps:
 1. Create a gRPC crypto client connection to the HPCS instance using the gRPC "Dial" function.
 2. Create a GREP11 gRPC request message using protobufs. See protos/server.proto for a complete list.
 3. Send the gRPC request message to the HPCS server instance.
 4. Receive the gRPC response from the HPCS server instance and check if an error occured.

The GREP11 name is derived from Enterprise PKCS #11 (EP11) over gRPC and adheres to the PKCS #11 2.40 specification.
See https://https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html.

The GREP11 API is contained within the protobuf source files in the protos directory and describes the Crypto service,
its methods, and the input and output (request and response) messages. For more information about the GREP11 API,
please visit https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-grep11-api-ref

As described in the hpcs-grep11-go README.md file, there are three different types of cipher
flows each consisting of a set of sub-operations that can be used for most GREP11 operations.
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

# Key Blobs

All key creation operations (GenerateKey, GenerateKeyPair, DeriveKey, and UnwrapKey) return an EP11 key blob (two EP11
key blobs for GenerateKeyPair -- private and public). All EP11 key blobs with the exception of public key blobs are encrypted
by the remote HSM. See the "EP11 Principles of Operation" (refer to README.md on how to access this document) for detailed
information about EP11 private and public key blobs.

The gRPC protobuf response message for GenerateKeyPair is used as example of a returning protobuf message containing EP11 key blobs:

	message GenerateKeyPairResponse {
		bytes PrivKeyBytes = 5;
		bytes PubKeyBytes = 6;
		KeyBlob PrivKey = 9;
		KeyBlob PubKey = 10;
	}

In the case of a GenerateKeyPair protobuf response, there are four fields in the response message. A "bytes" type field and "KeyBlob"
type field for both the private key (PrivKey) and public key (PubKey). The EP11 key blobs are returned from the server in two forms.
The first form is embedded in a byte slice containing the raw EP11 key blob (PrivKeyBytes or PubKeyBytes). The second form is embedded
in a "KeyBlob" protobuf message.

The "KeyBlob" protobuf message type used in key creation operations:

	message KeyBlob {
		bytes KeyBlobID = 1;
		int64 Version = 2;
		bytes TxID = 3;
		map<uint64,AttributeValue> Attributes = 4 [(gogoproto.castkey) = "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11.Attribute"];
		repeated bytes KeyBlobs = 5;
	}

The raw EP11 key blob is contained in the "KeyBlobs" field withing the "KeyBlob" protobuf message. The "KeyBlobs" field is a slice (array)
of byte slices and the raw EP11 key blob can be referenced using element 0 of the "KeyBlobs" field (e.g. KeyBlobs[0]). The KeyBlobID,
Version, and TxID fields are used internally by the remote server, and therefore, they should be ignored.  In addition to the "KeyBlobs"
field, the Attributes field contains attribute names and their respective values to the key contained in the "KeyBlobs" field.

NOTE: All non-key creation operations that require a key (e.g., encrypt, etc.) must specificy the "KeyBlob" protobuf version of
the EP11 key blob. For example, to perform an encrypt operation of some data using the public key from the GenerateKeyPairResponse message,
an EncryptSingleRequest protobuf message is created and sent to the remote server.

The EncryptSingleRequest protobuf message is defined as:

	message EncryptSingleRequest {
		Mechanism Mech = 2;
		bytes Plain = 3;
		KeyBlob Key = 5;
	}

The "Key" field of the EncryptSingleRequest protobuf message must contain a "KeyBlob" message type. As a result, in this example, the
EncryptSingleRequest message's "Key" field uses the "PubKey" field of the GeneateKeyPairResponse message and NOT the "PubKeyBytes" field.
The "PubKey" field is a "KeyBlob" type.

	encryptSingleRequest := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		Key:   generateKeyPairResponse.PubKey,
		Plain: plain,
	}

# Mechanism and Mechanism Parameters

The majority of crypto operations to the remote HSM requires a mechanism and, in some cases, an associated mechanism paramter. A mechanism
is an algorithm used for the crypto operation being performed. A list of supported mechanisms can be found in "pkg/ep11/header_consts.go".
Mechanism names are prefixed with "CKM_".

Some crypto operations require a mechanism parameter. There are several examples of how to configure mechanism parameters in the sample code.
All of the mechanism parameter types are defined in a protobuf message and each type of mechanism parameter has their own individual protobuf
message type. All of the mechanism parameter protobuf messages can be found in "protos/server.proto".

The following protobuf message defines how a mechanism and its mechanism parameter are defined:

	message Mechanism {
		uint64 Mechanism = 1 [(gogoproto.casttype) = "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11.Mechanism"];
		oneof Parameter {
			bytes ParameterB = 2;
			RSAOAEPParm RSAOAEPParameter = 3;
			RSAPSSParm RSAPSSParameter = 4;
			ECDH1DeriveParm ECDH1DeriveParameter = 5;
			BTCDeriveParm BTCDeriveParameter = 6;
			ECSGParm ECSGParameter = 7;
			KyberKEMParm KyberKEMParameter = 8;
			ECAGGParm ECAGGParameter = 9;
		}
	}

Currently there are eight different mechanism parameter types (defined in the "oneof Parameter" line). There are code examples
of how to use each of the above mentioned mechanism parameter types.

# Key Templates

For key creation operations (GenerateKey, GenerateKeyPair, DeriveKey, and UnwrapKey), you will be required to
supply key attributes. The attributes will vary depending on the type of key operation being performed.
Helper functions and a helper type have been provided to configure and properly format attributes associated with keys.
A complete list of supported attributes can be found in "pkg/ep11/header_consts.go". Attribute names are prefixed
with "CKA_".

The following code snippet shows how to use the helper functions and helper type for generating an RSA key pair.

	publicExponent := 65537
	publicKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_ENCRYPT:         true,
		ep11.CKA_VERIFY:          true,
		ep11.CKA_MODULUS_BITS:    4096,
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

Key creation operations return a protobuf message via gRPC, and the returned message contains a "KeyBlob" message type
as described above. One of the fields of the "KeyBlob" message is the "Attributes" field. The "Attributes" field contains
a map of key-value pairs representing key attribute names and their respective values. If you would like to inspect the attributes
of a "KeyBlob" message, a helper function "PrintAttributes" in "pkg/util/util.go" can be used to print out the key's attributes.

# Error Messages

The helper function, util.Convert(), can be used to extract information from the returned gRPC error data structure.
The Grep11Error data structure consists of a return code field whose value correlates with a standard PKCS11 error code. The
error codes can be found in the pkg/ep11/header_consts.go file. Error names are prefixed with "CKR_". In addition to the
return code, there may be additional information contained in the Details field of the Grep11Error data structure.

The following code snippet shows how the util.Convert() function is used to check for errors after a verify operation:

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

# IBM Cloud Identity Access and Management (IAM) Bearer Tokens

Helper functions and a helper data type (IAMPerRPCCredentials) are provided to request and manage bearer tokens obtained
from the IBM Cloud via IAM. The tokens are incorporated into the gRPC credentials dial option during the initial
connection (gRPC Dial) through the use of the GetRequestMetadata and getToken helper functions contained
in pkg/authorize/authorize.go.

Prior to running the sample code, there are two environment variables that must be set to ensure that the connection is authorized:

 1. GREP11_ADDRESS - The full Enterprise PKCS #11 endpoint URL. This can be obtained by navigating
    to your HPCS instance's main page via the IBM Cloud UI, expanding the "Enterprise PKCS #11 endpoint URL"
    section and copying either the "Public" or "Private" URL.  If the URL does not contain a port then append ":443"
    to the Enterprise PKCS #11 endpoint URL. Example: "7fc144ef-ed7c-4be1-9a35-748b40477dcd.ep11.hs-crypto.appdomain.cloud:443"

    NOTE: The use of either the public or private endpoint is dependent on what network is being used to access the remote server

 2. GREP11_APIKEY - An IAM API key associated with the HPCS instance being accessed.

Optionally, The values of the two environment variables listed above can be hardcoded in the main.go file. Replace the
values of the ClientConfig.Address and ClientConfig.APIKey variable fields with the values related to your HPCS instance.
*/
package examples
