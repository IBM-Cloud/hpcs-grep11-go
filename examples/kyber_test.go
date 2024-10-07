/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// The starting offset of the Kyber mechanism parameter, CipherText, for decapsulation operations
const cipherTextOffset uint = 7

// ecdhInfo is used for the Kyber examples
type ecdhInfo struct {
	bitLen     int
	curveIDStr string
	curveID    asn1.ObjectIdentifier
	mechanism  ep11.Mechanism
}

// Test_kyber_standard_encapsulate_decapsulate performs a basic encapsulation and
// decapsulation of a derived AES key using a Kyber key pair
//
// NOTE: This test can only be run on CEX8 crypto cards within an IBM Z processor complex
//
// Flow: connect, generate a Kyber key pair, derive an AES key using the Kyber public
// key for encapsulation, encrypt some sample data using the derived AES key,
// decapsulate the encrypted AES key by performing a derive operation using the
// Kyber private key, decrypt the encrypted sample message using the decapsulated AES key
func Test_kyber_standard_encapsulate_decapsulate(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Check to see if the CKM_IBM_KYBER mechanism is supported on the remote HSM
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_KYBER) {
		t.Skip("Kyber mechanism (CKM_IBM_KYBER) is not supported on the remote HSM")
	}

	kyberStrengthParam, err := asn1.Marshal(util.OIDKyberR2High)
	if err != nil {
		panic(fmt.Errorf("Error marshalling Kyber strength: %s", err))
	}

	publicKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:          ep11.CKO_PUBLIC_KEY,
		ep11.CKA_IBM_PQC_PARAMS: kyberStrengthParam,
		ep11.CKA_ENCRYPT:        true,
		ep11.CKA_DERIVE:         true,
	}
	privateKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:   ep11.CKO_PRIVATE_KEY,
		ep11.CKA_DECRYPT: true,
		ep11.CKA_DERIVE:  true,
	}
	kyberKeyPairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_IBM_KYBER},
		PubKeyTemplate:  util.AttributeMap(publicKyberKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKyberKeyTemplate),
	}

	// Kyber key pair generation
	kyberKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), kyberKeyPairRequest)
	if err != nil {
		panic(fmt.Errorf("Error occurred when generating a Kyber key pair: %s", err))
	}

	fmt.Println("Generated Kyber key pair")

	deriveKyberTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 256 / 8,
	}

	// Derive an encapsulated symmetric key using the Kyber public key
	deriveReqEnc := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_KYBER,
			Parameter: &pb.Mechanism_KyberKEMParameter{
				KyberKEMParameter: &pb.KyberKEMParm{
					Version: 0,
					Mode:    pb.KyberKEMParm_CkIbmKEMEncapsulate,
					Kdf:     pb.KyberKEMParm_CkdNull, // The null kdf is used for basic encapsulation
				},
			},
		},
		BaseKey:  kyberKeyPairResponse.PubKey,
		Template: util.AttributeMap(deriveKyberTemplate),
	}

	// The derived AES key is contained in the NewKey field of the response.
	// The AES key in the NewKey field is a normal AES key blob that is wrapped/encrypted
	// using a key inside the HSM itself.
	//
	// The derived AES key is also contained in the CheckSum field of the derived key response.
	// However, the AES key is encapsulated/encrypted by the Kyber private key.  The starting
	// byte of the encapsulated AES key begins at offset 7 (8th byte) within the CheckSum field.
	//
	// A Golang constant is defined within this example package, "cipherTextOffset", and
	// represents the offset location of the encapsulated key.  This constant variable is
	// used below for the Kyber "decapsulation" of the AES key.

	deriveRespEnc, err := cryptoClient.DeriveKey(context.Background(), deriveReqEnc)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error when deriving an AES key: %s", err))
	}

	fmt.Println("Derived AES key was encapsulated by Kyber public key")

	// Encrypt data with the AES key
	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	data := []byte("Testing this function for Kyber")

	encryptReqEnc := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   deriveRespEnc.NewKey,
		Plain: data,
	}

	encryptRespEnc, err := cryptoClient.EncryptSingle(context.Background(), encryptReqEnc)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	fmt.Println("Sample data was encrypted by derived AES key")

	// Now decapsulate the hybrid AES key.
	// The KDF used in the encapsulation operation must also be used for the decapsulation operation.
	deriveReqDec := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_KYBER,
			Parameter: &pb.Mechanism_KyberKEMParameter{
				KyberKEMParameter: &pb.KyberKEMParm{
					Version:    0,
					Mode:       pb.KyberKEMParm_CkIbmKEMDecapsulate,
					Kdf:        pb.KyberKEMParm_CkdNull,                   // The null kdf is used for basic decapsulation
					CipherText: deriveRespEnc.CheckSum[cipherTextOffset:], // Always start at offset 7 (8th byte) for CheckSum
				},
			},
		},
		BaseKey:  kyberKeyPairResponse.PrivKey,
		Template: util.AttributeMap(deriveKyberTemplate),
	}

	deriveRespDec, err := cryptoClient.DeriveKey(context.Background(), deriveReqDec)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error when extracting encapsulated AES key: %s", err))
	}

	fmt.Println("Encapsulated AES key was decapsulated by Kyber private key")

	// Use the decapsulated AES key to decrypt data that was encrypted after encapsulation
	decryptReq := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      deriveRespDec.NewKey,
		Ciphered: encryptRespEnc.Ciphered,
	}

	_, err = cryptoClient.DecryptSingle(context.Background(), decryptReq)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}

	fmt.Println("Sample data was decrypted by decapsulated AES key")

	// Output:
	// Generated Kyber key pair
	// Derived AES key was encapsulated by Kyber public key
	// Sample data was encrypted by derived AES key
	// Encapsulated AES key was decapsulated by Kyber private key
	// Sample data was decrypted by decapsulated AES key
}

// Test_kyber_hybrid performs Kyber encapsulation and decapsulation operations
// using a shared generic secret key derived from an ECDSA key pair. This variation
// is call hybrid key generation.
//
// NOTE: This test can only be run on CEX8 crypto cards within an IBM Z processor complex
//
// Flow: connect, generate a Kyber key pair, generate an EC key pair,
// derive a generic secret key from the EC key pair,
// derive an AES key using the Kyber public key and generic secret key
// for encapsulation, encrypt some sample data using the derived AES key,
// decapsulate the encrypted AES key by performing a derive operation using the
// Kyber private key and the generic secret key, decrypt the encrypted
// sample message using the decapsulated AES key
func Test_kyber_hybrid(t *testing.T) {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Check to see if the CKM_IBM_KYBER mechanism is supported on the remote HSM
	if !util.MechanismExists(cryptoClient, ep11.CKM_IBM_KYBER) {
		t.Skip("Kyber mechanism (CKM_IBM_KYBER) is not supported on the remote HSM")
	}

	strengths := map[string]asn1.ObjectIdentifier{
		"r2rec":  util.OIDKyberR2Rec,
		"r2high": util.OIDKyberR2High,
	}

	kdfs := map[string]pb.KyberKEMParm_KyberDeriveType{
		"sha1":   pb.KyberKEMParm_CkdIbmHybridSha1Kdf,
		"sha224": pb.KyberKEMParm_CkdIbmHybridSha224Kdf,
		"sha256": pb.KyberKEMParm_CkdIbmHybridSha256Kdf,
		"sha384": pb.KyberKEMParm_CkdIbmHybridSha384Kdf,
		"sha512": pb.KyberKEMParm_CkdIbmHybridSha512Kdf,
	}

	ecdhCurves := []ecdhInfo{
		{224, "OIDNamedCurveP224", util.OIDNamedCurveP224, ep11.CKM_ECDH1_DERIVE},
		{256, "OIDNamedCurveP256", util.OIDNamedCurveP256, ep11.CKM_ECDH1_DERIVE},
		{384, "OIDNamedCurveP384", util.OIDNamedCurveP384, ep11.CKM_ECDH1_DERIVE},
		{528, "OIDNamedCurveP521", util.OIDNamedCurveP521, ep11.CKM_ECDH1_DERIVE},
		{256, "OIDNamedCurveSecp256k1", util.OIDNamedCurveSecp256k1, ep11.CKM_ECDH1_DERIVE},
		{256, "OIDNamedCurveX25519", util.OIDNamedCurveX25519, ep11.CKM_IBM_EC_X25519},
		{448, "OIDNamedCurveX448", util.OIDNamedCurveX448, ep11.CKM_IBM_EC_X448},
	}

	// Test hybrid key generation along with encapsulation and decapsulation
	// operations. An AES key is derived and used for encryption and decryption.
	//
	// Examples include all strengths and KDFs. In addition, different key lengths and curves
	// are used to derive the ECDH generic secret (used for hybrid key generation).
	for _, strength := range strengths {
		for _, ecdhCurve := range ecdhCurves {
			for _, kdf := range kdfs {
				testKyberHybridDerive(cryptoClient, strength, kdf, ecdhCurve)
			}
		}
	}

	fmt.Println("Successfully ran all Kyber examples")

	// Output:
	// Successfully ran all Kyber examples
}

func testKyberHybridDerive(cryptoClient pb.CryptoClient, strength asn1.ObjectIdentifier, kdf pb.KyberKEMParm_KyberDeriveType,
	ecdhCurve ecdhInfo) {
	kyberStrengthParam, err := asn1.Marshal(strength)
	if err != nil {
		panic(fmt.Errorf("Error marshalling Kyber strength: %s", err))
	}

	publicKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:          ep11.CKO_PUBLIC_KEY,
		ep11.CKA_IBM_PQC_PARAMS: kyberStrengthParam,
		ep11.CKA_ENCRYPT:        true,
		ep11.CKA_DERIVE:         true,
	}
	privateKyberKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:   ep11.CKO_PRIVATE_KEY,
		ep11.CKA_DECRYPT: true,
		ep11.CKA_DERIVE:  true,
	}
	kyberKeyPairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_IBM_KYBER},
		PubKeyTemplate:  util.AttributeMap(publicKyberKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKyberKeyTemplate),
	}

	// Kyber key pair generation
	kyberKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), kyberKeyPairRequest)
	if err != nil {
		panic(fmt.Errorf("Error occurred when generating a Kyber key pair: %s", err))
	}

	// Define key derive templates
	// NOTE: The length of the derived generic secret key (CKA_VALUE_LEN) and the length of
	// the EC curve (ecdhCurve.curveID) used in the ECDH derive operation must be the same.
	deriveECDHTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
		ep11.CKA_VALUE_LEN:       ecdhCurve.bitLen / 8,
		ep11.CKA_IBM_USE_AS_DATA: true,
	}

	deriveKyberTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_SECRET_KEY,
		ep11.CKA_KEY_TYPE:  ep11.CKK_AES,
		ep11.CKA_VALUE_LEN: 256 / 8,
	}

	// Generate EC key pair for generic secret key derivation
	ecParameters, err := asn1.Marshal(ecdhCurve.curveID)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	publicECKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:     ep11.CKO_PUBLIC_KEY,
		ep11.CKA_EC_PARAMS: ecParameters,
		ep11.CKA_DERIVE:    true,
	}
	privateECKeyTemplate := ep11.EP11Attributes{
		ep11.CKA_CLASS:  ep11.CKO_PRIVATE_KEY,
		ep11.CKA_DERIVE: true,
	}
	ecKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicECKeyTemplate),
		PrivKeyTemplate: util.AttributeMap(privateECKeyTemplate),
	}

	ecKeyPairResp, err := cryptoClient.GenerateKeyPair(context.Background(), ecKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair error: %s", err))
	}

	// Create a CKK_GENERIC_SECRET using the CKM_ECDH1_DERIVE mechanism and a KDF of CKD_IBM_HYBRID_NULL
	pubECCoordinates, err := util.GetECPointFromSPKI(ecKeyPairResp.PubKey.KeyBlobs[0])
	if err != nil {
		panic(fmt.Errorf("Could not extract EC Point from public key: %s", err))
	}

	deriveReqECDH := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ecdhCurve.mechanism,
			Parameter: &pb.Mechanism_ECDH1DeriveParameter{
				ECDH1DeriveParameter: &pb.ECDH1DeriveParm{
					Kdf:        pb.ECDH1DeriveParm_CkdIbmHybridNull,
					PublicData: pubECCoordinates,
				},
			}},
		BaseKey:  ecKeyPairResp.PrivKey,
		Template: util.AttributeMap(deriveECDHTemplate),
	}

	deriveRespECDH, err := cryptoClient.DeriveKey(context.Background(), deriveReqECDH)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error when deriving a secret key: %s", err))
	}

	// Now use the ECDH derived generic secret key to derive an AES key using Kyber KEM
	deriveReqEnc := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_KYBER,
			Parameter: &pb.Mechanism_KyberKEMParameter{
				KyberKEMParameter: &pb.KyberKEMParm{
					Version: 0,
					Mode:    pb.KyberKEMParm_CkIbmKEMEncapsulate,
					Kdf:     kdf,
					Blob:    deriveRespECDH.NewKey.KeyBlobs[0],
				},
			},
		},
		BaseKey:  kyberKeyPairResponse.PubKey,
		Template: util.AttributeMap(deriveKyberTemplate),
	}

	// The derived AES key is contained in the NewKey field of the response.
	// The AES key in the NewKey field is a normal AES key blob that is wrapped/encrypted
	// using a key inside the HSM itself.
	//
	// The derived AES key is also contained in the CheckSum field of the derived key response.
	// However, the AES key is encapsulated/encrypted by the Kyber private key.  The starting
	// byte of the encapsulated AES key begins at offset 7 (8th byte) within the CheckSum field.
	//
	// A Golang constant is defined within this example package, "cipherTextOffset", and
	// represents the offset location of the encapsulated key.  This constant variable is
	// used below for the Kyber "decapsulation" of the AES key.

	deriveRespEnc, err := cryptoClient.DeriveKey(context.Background(), deriveReqEnc)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error when deriving an AES key: %s", err))
	}

	// Encrypt data with the AES key
	// Obtain initialization vector for encrypt and decrypt operations
	iv, err := util.GenerateIV(cryptoClient, util.AESBlkSize)
	if err != nil {
		panic(fmt.Errorf("Generate IV error: %s", err))
	}

	data := []byte("Testing this function for Kyber")

	encryptReqEnc := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:   deriveRespEnc.NewKey,
		Plain: data,
	}

	encryptRespEnc, err := cryptoClient.EncryptSingle(context.Background(), encryptReqEnc)
	if err != nil {
		panic(fmt.Errorf("EncryptSingle error: %s", err))
	}

	// Now decapsulate the hybrid AES key.
	// The KDF used in the encapsulation operation must also be used for the decapsulation operation.
	// In addition, the ECDH generic secret key must be supplied.
	deriveReqDec := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_KYBER,
			Parameter: &pb.Mechanism_KyberKEMParameter{
				KyberKEMParameter: &pb.KyberKEMParm{
					Version:    0,
					Mode:       pb.KyberKEMParm_CkIbmKEMDecapsulate,
					Kdf:        kdf,
					CipherText: deriveRespEnc.CheckSum[cipherTextOffset:], // Always start at offset 7 (8th byte) for CheckSum
					Blob:       deriveRespECDH.NewKey.KeyBlobs[0],
				},
			},
		},
		BaseKey:  kyberKeyPairResponse.PrivKey,
		Template: util.AttributeMap(deriveKyberTemplate),
	}

	deriveRespDec, err := cryptoClient.DeriveKey(context.Background(), deriveReqDec)
	if err != nil {
		panic(fmt.Errorf("DeriveKey error when extracting encapsulated AES key: %s", err))
	}

	// Use the decapsulated AES key to decrypt data that was encrypted after encapsulation
	decryptReq := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: util.SetMechParm(iv)},
		Key:      deriveRespDec.NewKey,
		Ciphered: encryptRespEnc.Ciphered,
	}

	_, err = cryptoClient.DecryptSingle(context.Background(), decryptReq)
	if err != nil {
		panic(fmt.Errorf("DecryptSingle error: %s", err))
	}
}
