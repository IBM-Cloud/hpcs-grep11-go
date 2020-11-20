/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/util"
	grpc "google.golang.org/grpc"
)

const hardened = 0x80000000 // For ED25519 only hardened key generation from Private parent key to private child key is supported.

// Example_slip10DeriveKey derives sets of privte/public key pairs using SLIP10
// Flow: connect, generate generic secret key, derive keys using SLIP10, and validates the derived keys by signing and verifying data
func Example_slip10DeriveKey() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// SLIP10 has been verified for NIST P-256, Secp256k1 and Ed25519
	supportedCurves := []asn1.ObjectIdentifier{util.OIDNamedCurveP256, util.OIDNamedCurveSecp256k1, util.OIDNamedCurveED25519}
	for _, oid := range supportedCurves {
		fmt.Printf("Curve: %+v\n", oid)
		slip10TestCurve(cryptoClient, oid)
	}

	// Output:
	// Curve: 1.2.840.10045.3.1.7
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Curve: 1.3.132.0.10
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Curve: 1.3.101.112
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
}

func slip10TestCurve(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier) {
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				ep11.CKA_VALUE_LEN:       256 / 8,
				ep11.CKA_WRAP:            false,
				ep11.CKA_UNWRAP:          false,
				ep11.CKA_SIGN:            true,
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_IBM_USE_AS_DATA: true,
			},
		),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generic Secret Key error: %+v %s", generateKeyRequest, err))
	}

	fmt.Println("Generated Generic Secret Key")

	masterSecretKey, masterChainCode := slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		oid,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)

	const maxDepth = 3
	const maxChild = 3
	var privateKey [maxDepth][maxChild][]byte
	var privateChainCode [maxDepth][maxChild][]byte
	var publicKey [maxDepth][maxChild][]byte
	var publicChainCode [maxDepth][maxChild][]byte
	var child, depth uint64

	for child = 0; child < maxChild; child++ {
		privateKey[0][child], privateChainCode[0][child] = slip10DeriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
			oid,
			child+hardened,
			masterSecretKey,
			masterChainCode,
		)
		publicKey[0][child], publicChainCode[0][child] = slip10DeriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
			oid,
			child+hardened,
			masterSecretKey,
			masterChainCode,
		)
	}
	for depth = 1; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			privateKey[depth][child], privateChainCode[depth][child] = slip10DeriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
				oid,
				child+hardened,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			publicKey[depth][child], publicChainCode[depth][child] = slip10DeriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
				oid,
				child+hardened,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			// PUB2PUB is not supported yet
			/*
				publicKey[depth][child], publicChainCode[depth][child] = slip10DeriveKey(
					cryptoClient,
					pb.BTCDeriveParm_CkSLIP0010PUB2PUB,
					oid,
					child,
					publicKey[depth-1][child],
					publicChainCode[depth-1][child],
				)
			*/
		}
	}
	for depth = 0; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			slip10DeriveKeySlip10SignAndVerifySingle(cryptoClient, oid, privateKey[depth][child], publicKey[depth][child])
		}
	}
}

func slip10DeriveKey(cryptoClient pb.CryptoClient, deriveType pb.BTCDeriveParm_BTCDeriveType, oid asn1.ObjectIdentifier, childKeyIndex uint64, baseKey []byte, chainCode []byte) ([]byte, []byte) {
	ecParameters, err := asn1.Marshal(oid)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	deriveKeyRequest := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          deriveType,
					ChildKeyIndex: childKeyIndex,
					ChainCode:     chainCode,
					Version:       1,
				},
			},
		},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
				ep11.CKA_VALUE_LEN:       0,
				ep11.CKA_IBM_USE_AS_DATA: true,
				ep11.CKA_EC_PARAMS:       ecParameters,
			},
		),
		BaseKey: baseKey,
	}
	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Derived Child Key error: %+v error: %s", deriveKeyRequest, err))
	}

	fmt.Printf("Derived Key type=%s index=%d\n",
		pb.BTCDeriveParm_BTCDeriveType_name[(int32)(deriveType)], childKeyIndex)

	return deriveKeyResponse.NewKeyBytes, deriveKeyResponse.CheckSum
}

func slip10SignAndVerify(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {
	mech, err := util.GetSignMechanismFromOID(oid)
	if err != nil {
		panic(fmt.Errorf("Unexpected OID: %+v", oid))
	}

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: mech},
		PubKey: publicKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		}
		panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
	}

	fmt.Println("Signature verified")
	return true
}

func slip10DeriveKeySlip10SignAndVerifySingle(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {
	mech, err := util.GetSignMechanismFromOID(oid)
	if err != nil {
		panic(fmt.Errorf("Unexpected OID: %+v", oid))
	}

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Println("Data signed")

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: mech},
		PubKey:    publicKey,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Signature verified")
	return true
}

// Example_slip10CrossSignAndVerify derives sets of private/public key pairs using SLIP10
// Flow: connect, generate generic secret key, derive keys using SLIP10, and validates the derived keys by signing and verifying data
func Example_slip10CrossSignAndVerify() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// SLIP10 has been verified for NIST P-256, Secp256k1 and Ed25519
	// util.OIDNamedCurveP256, util.OIDNamedCurveSecp256k1, util.OIDNamedCurveED25519

	// Generate a random seed key
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				ep11.CKA_VALUE_LEN:       256 / 8,
				ep11.CKA_WRAP:            false,
				ep11.CKA_UNWRAP:          false,
				ep11.CKA_SIGN:            true,
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_IBM_USE_AS_DATA: true,
			},
		),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generic Secret Key error: %+v %s", generateKeyRequest, err))
	}

	fmt.Println("Generated Generic Secret Key")

	// Keys of NIST P-256
	var publicKeyP256, privateKeyP256 []byte
	masterSecretKeyP256, masterChainCodeP256 := slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveP256,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKeyP256, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKeyP256,
		masterChainCodeP256,
	)
	publicKeyP256, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKeyP256,
		masterChainCodeP256,
	)

	// Keys of Secp256k1
	var privateKey256k1, publicKey256k1 []byte
	masterSecretKey256k1, masterChainCode256k1 := slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveSecp256k1,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey256k1, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey256k1,
		masterChainCode256k1,
	)
	publicKey256k1, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey256k1,
		masterChainCode256k1,
	)

	// Keys of ED25519
	var privateKeyEd25519, publicKeyEd25519 []byte
	masterSecretKeyEd25519, masterChainCodeEd25519 := slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveED25519,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKeyEd25519, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKeyEd25519,
		masterChainCodeEd25519,
	)
	publicKeyEd25519, _ = slip10DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKeyEd25519,
		masterChainCodeEd25519,
	)

	// SignSingle, and VerifyInit/Verify
	slip10SignSingleAndVerify(cryptoClient, util.OIDNamedCurveP256, privateKeyP256, publicKeyP256)
	slip10SignSingleAndVerify(cryptoClient, util.OIDNamedCurveSecp256k1, privateKey256k1, publicKey256k1)
	slip10SignSingleAndVerify(cryptoClient, util.OIDNamedCurveED25519, privateKeyEd25519, publicKeyEd25519)
	// SignInit/Sign, VerifySingle
	slip10SignAndVerifySingle(cryptoClient, util.OIDNamedCurveP256, privateKeyP256, publicKeyP256)
	slip10SignAndVerifySingle(cryptoClient, util.OIDNamedCurveSecp256k1, privateKey256k1, publicKey256k1)
	slip10SignAndVerifySingle(cryptoClient, util.OIDNamedCurveED25519, privateKeyEd25519, publicKeyEd25519)

	// Output:
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Data signed - 1.2.840.10045.3.1.7
	// Signature verified - 1.2.840.10045.3.1.7
	// Data signed - 1.3.132.0.10
	// Signature verified - 1.3.132.0.10
	// Data signed - 1.3.101.112
	// Signature verified - 1.3.101.112
	// Data signed - 1.2.840.10045.3.1.7
	// Signature verified - 1.2.840.10045.3.1.7
	// Data signed - 1.3.132.0.10
	// Signature verified - 1.3.132.0.10
	// Data signed - 1.3.101.112
	// Signature verified - 1.3.101.112
}

func slip10SignSingleAndVerify(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {
	mech, err := util.GetSignMechanismFromOID(oid)
	if err != nil {
		panic(fmt.Errorf("Unexpected OID: %+v", oid))
	}

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	fmt.Printf("Data signed - %s\n", oid)

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: mech},
		PubKey: publicKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		}
		panic(fmt.Errorf("Verify error: %d: %s", ep11Status.Code, ep11Status.Detail))
	}

	fmt.Printf("Signature verified - %s\n", oid)
	return true
}

func slip10SignAndVerifySingle(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {
	mech, err := util.GetSignMechanismFromOID(oid)
	if err != nil {
		panic(fmt.Errorf("Unexpected OID: %+v", oid))
	}

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}

	fmt.Printf("Data signed - %s\n", oid)

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: mech},
		PubKey:    publicKey,
		Data:      signData,
		Signature: signResponse.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Printf("Signature verified - %s\n", oid)
	return true
}
