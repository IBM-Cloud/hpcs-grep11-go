/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/IBM-Cloud/hpcs-grep11-go/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/util"
	grpc "google.golang.org/grpc"
)

// Example_bip32_Base
// Flow: generate 256 bit random seed => generate master node => derive master key m => derive wallet account key m/0
// => derive wallet chain keypair m/0/0 => derive address key m/0/0/0 => sign/verify ECDSA
// => base test covers private->private private->public key derivation
func Example_bip32_Base() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Println("Generating random seed key...")

	keyTemplate := ep11.EP11Attributes{
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
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generated Generic Secret Key error: %+v %s", generateKeyRequest, err))
	}
	const maxDepth = 3
	const maxChild = 1

	var privateKey [maxDepth][maxChild][]byte
	var privateChainCode [maxDepth][maxChild][]byte
	var publicKey [maxDepth][maxChild][]byte
	var publicChainCode [maxDepth][maxChild][]byte
	var child, depth uint64

	fmt.Println("Depth0: Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Depth0: Generated master key from random seed and master chaincode")

	fmt.Println("Depth1: Generating wallet accounts...")
	privateKey[0][0], privateChainCode[0][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		masterSecretKey,
		masterChainCode,
	)
	publicKey[0][0], publicChainCode[0][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)

	fmt.Println("Depth1: Generated external and internal wallet accounts")

	fmt.Println("Depth2: Generating wallet chains...")
	privateKey[1][0], privateChainCode[1][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey[0][0],
		privateChainCode[0][0],
	)
	publicKey[1][0], publicChainCode[1][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey[0][0],
		privateChainCode[0][0],
	)

	fmt.Println("Depth2: Generated internal and external wallet chain successfully")

	fmt.Println("Depth3: Generating wallet addresses...")
	privateKey[2][0], privateChainCode[2][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey[1][0],
		privateChainCode[1][0],
	)
	publicKey[2][0], publicChainCode[2][0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey[1][0],
		privateChainCode[1][0],
	)
	fmt.Println("Depth3: Generated external and internal addresses successfully.")

	for depth = 0; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			bip32SignAndVerify(cryptoClient, privateKey[depth][child], publicKey[depth][child])
		}
	}
	fmt.Println("Sign and verify")

	for depth = 0; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			bip32SignAndVerifySingle(cryptoClient, privateKey[depth][child], publicKey[depth][child])
		}
	}
	fmt.Println("SignSingle and VerifySingle completed successfully")

	// Output:
	// Generating random seed key...
	// Depth0: Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Depth0: Generated master key from random seed and master chaincode
	// Depth1: Generating wallet accounts...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth1: Generated external and internal wallet accounts
	// Depth2: Generating wallet chains...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth2: Generated internal and external wallet chain successfully
	// Depth3: Generating wallet addresses...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth3: Generated external and internal addresses successfully.
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Sign and verify
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// SignSingle and VerifySingle completed successfully
}

// Example_bip32_KeyDerivation covers private->private public->public key derivations
func Example_bip32_KeyDerivation() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Println("Generating random seed key...")

	keyTemplate := ep11.EP11Attributes{
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
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generated Generic Secret Key error: %+v %s", generateKeyRequest, err))
	}

	var publicKey []byte
	var publicChainCode []byte

	fmt.Println("Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Generated master key from random seed and master chaincode")

	fmt.Println("Generating wallet accounts...")
	publicKey, publicChainCode = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)
	fmt.Println("Derived key from private -> public")

	privKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true,
		ep11.CKA_EXTRACTABLE:     false,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
		ep11.CKA_VALUE_LEN:       0,
		ep11.CKA_IBM_USE_AS_DATA: true,
	}

	deriveKeyRequestPri := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          pb.BTCDeriveParm_CkBIP0032PRV2PRV,
					ChildKeyIndex: 0,
					ChainCode:     masterChainCode,
					Version:       1,
				},
			},
		},
		Template: util.AttributeMap(privKeyTemplate),
		BaseKey:  masterSecretKey,
	}
	_, err = cryptoClient.DeriveKey(context.Background(), deriveKeyRequestPri)
	if err != nil {
		fmt.Println("Deriving keys from public to public is currently not supported")
	} else {
		fmt.Println("Derived key from private -> private")
	}

	pubKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true,
		ep11.CKA_EXTRACTABLE:     false,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
		ep11.CKA_VALUE_LEN:       0,
		ep11.CKA_IBM_USE_AS_DATA: true,
	}

	deriveKeyRequestPub := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          pb.BTCDeriveParm_CkBIP0032PUB2PUB,
					ChildKeyIndex: 0,
					ChainCode:     publicChainCode,
					Version:       1,
				},
			},
		},
		Template: util.AttributeMap(pubKeyTemplate),
		BaseKey:  publicKey,
	}
	deriveKeyResponsePub, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequestPub)
	if err != nil {
		fmt.Println("Deriving keys from public to public is currently not supported")
	} else {
		fmt.Printf("Derived key from public to public successfully: %v", deriveKeyResponsePub)
	}

	// Output:
	// Generating random seed key...
	// Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Generated master key from random seed and master chaincode
	// Generating wallet accounts...
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Derived key from private -> public
	// Derived key from private -> private
	// Deriving keys from public to public is currently not supported
}

// Example_bip32_Cross_SignVerify performs cross sign and verification operations
func Example_bip32_Cross_SignVerify() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Println("Generating random seed key...")

	keyTemplate := ep11.EP11Attributes{
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
	}

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(keyTemplate),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generic Secret Key error: %+v %s", generateKeyRequest, err))
	}

	fmt.Println("Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Generated master key from random seed and master chaincode")

	var privateKeyW [3][]byte
	var privateKeyChainCodeW [3][]byte
	var publicKeyW [3][]byte
	var publicChainCodeW [3][]byte

	privateKeyW[0], privateKeyChainCodeW[0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		masterSecretKey,
		masterChainCode,
	)
	publicKeyW[0], publicChainCodeW[0] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)
	fmt.Println("Depth1: Generated external and internal wallet accounts")
	bip32SignAndVerifySingle(cryptoClient, privateKeyW[0], publicKeyW[0])

	privateKeyW[1], privateKeyChainCodeW[1] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKeyW[0],
		privateKeyChainCodeW[0],
	)
	publicKeyW[1], publicChainCodeW[1] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKeyW[0],
		privateKeyChainCodeW[0],
	)
	fmt.Println("Depth2: Generated internal and external wallet chain successfully")
	bip32SignAndVerifySingle(cryptoClient, privateKeyW[1], publicKeyW[1])

	privateKeyW[2], privateKeyChainCodeW[2] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKeyW[1],
		privateKeyChainCodeW[1],
	)
	publicKeyW[2], publicChainCodeW[2] = bip32DeriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKeyW[1],
		privateKeyChainCodeW[1],
	)
	fmt.Println("Depth3: Generated external and internal addresses successfully.")
	bip32SignAndVerifySingle(cryptoClient, privateKeyW[2], publicKeyW[2])

	fmt.Println("Round 1: Cross verification")
	signData1 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest1 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKeyW[2],
		Data:    signData1,
	}
	signSingleResponse1, err := cryptoClient.SignSingle(context.Background(), signSingleRequest1)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest1 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKeyW[1],
		Data:      signData1,
		Signature: signSingleResponse1.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest1)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 1: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Round 2: Cross verification")
	signData2 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest2 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKeyW[1],
		Data:    signData2,
	}
	signSingleResponse2, err := cryptoClient.SignSingle(context.Background(), signSingleRequest2)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest2 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKeyW[0],
		Data:      signData2,
		Signature: signSingleResponse2.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest2)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 2: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Round 3: Cross verification")
	signData3 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest3 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKeyW[0],
		Data:    signData3,
	}
	signSingleResponse3, err := cryptoClient.SignSingle(context.Background(), signSingleRequest3)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest3 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKeyW[2],
		Data:      signData3,
		Signature: signSingleResponse3.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest3)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 3: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	//Output:
	// Generating random seed key...
	// Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Generated master key from random seed and master chaincode
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth1: Generated external and internal wallet accounts
	// Data signed
	// Signature verified
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth2: Generated internal and external wallet chain successfully
	// Data signed
	// Signature verified
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth3: Generated external and internal addresses successfully.
	// Data signed
	// Signature verified
	// Round 1: Cross verification
	// Round 1: Invalid signature
	// Round 2: Cross verification
	// Round 2: Invalid signature
	// Round 3: Cross verification
	// Round 3: Invalid signature
}

func bip32DeriveKey(cryptoClient pb.CryptoClient, deriveType pb.BTCDeriveParm_BTCDeriveType, childKeyIndex uint64, baseKey []byte, chainCode []byte) ([]byte, []byte) {
	keyTemplate := ep11.EP11Attributes{
		ep11.CKA_VERIFY:          true,
		ep11.CKA_EXTRACTABLE:     false,
		ep11.CKA_DERIVE:          true,
		ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
		ep11.CKA_VALUE_LEN:       0,
		ep11.CKA_IBM_USE_AS_DATA: true,
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
		Template: util.AttributeMap(keyTemplate),
		BaseKey:  baseKey,
	}
	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Derived Child Key request: %+v error: %s", deriveKeyRequest, err))
	} else {
		fmt.Printf("Derived Key type=%s index=%d\n",
			pb.BTCDeriveParm_BTCDeriveType_name[(int32)(deriveType)], childKeyIndex)
	}

	return deriveKeyResponse.NewKeyBytes, deriveKeyResponse.CheckSum
}

func bip32SignAndVerify(cryptoClient pb.CryptoClient, privateKey []byte, publicKey []byte) bool {
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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

	// Modify signature to force returned error code
	//SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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

func bip32SignAndVerifySingle(cryptoClient pb.CryptoClient, privateKey []byte, publicKey []byte) bool {
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	} else {
		fmt.Println("Data signed")
	}

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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
