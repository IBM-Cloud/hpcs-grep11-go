/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package util provides helper data types and functions for the GREP11 examples
package util

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var lock sync.RWMutex
var (
	// The following variables are standardized elliptic curve definitions
	OIDNamedCurveP224      = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OIDNamedCurveP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDNamedCurveP384      = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDNamedCurveP521      = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	OIDNamedCurveX25519    = asn1.ObjectIdentifier{1, 3, 101, 110}
	OIDNamedCurveX448      = asn1.ObjectIdentifier{1, 3, 101, 111}
	OIDNamedCurveED25519   = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDNamedCurveED448     = asn1.ObjectIdentifier{1, 3, 101, 113}

	// The following variables are regular brainpool elliptic curve definitions
	OIDBrainpoolP160r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 1}
	OIDBrainpoolP192r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 3}
	OIDBrainpoolP224r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 5}
	OIDBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	OIDBrainpoolP320r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 9}
	OIDBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}

	// The following variables are twisted brainpool elliptic curve definitions
	OIDBrainpoolP160t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 2}
	OIDBrainpoolP192t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 4}
	OIDBrainpoolP224t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 6}
	OIDBrainpoolP256t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}
	OIDBrainpoolP320t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 10}
	OIDBrainpoolP384t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}

	// Public key object identifiers
	OIDECPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDRSAPublicKey = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDDSAPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}     // RFC 3279, 2.3.2  DSA Signature Keys
	OIDDHPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1} // PKCS#3, 9. Object identifier

	// Supported Dilithium round 2 strengths with SHAKE-256 as PRF
	OIDDilithiumHigh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 1, 6, 5}
	OIDDilithium87   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 1, 8, 7}

	// Supported Dilithium round 3 strengths with SHAKE-256 as PRF
	OIDDilithiumR3Weak  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	OIDDilithiumR3Rec   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5}
	OIDDilithiumR3VHigh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}

	// Supported Kyber round 2 strengths with SHAKE-128 as PRF
	OIDKyberR2Rec  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 5, 3, 3}
	OIDKyberR2High = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 5, 4, 4}

	// Supported BLS12-381 OIDs
	OIDBLS12_381ET = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 999, 3, 2}
)

// BlockType and the associated constants defined below are used for the GenerateIV helper function
type BlockType int

const (
	// AESBlkSize represents the AES block size in bytes
	AESBlkSize BlockType = ep11.AES_BLOCK_SIZE
	// DESBlkSize represents the DES block size in bytes
	DESBlkSize BlockType = ep11.DES_BLOCK_SIZE
)

// ecKeyIdentificationASN defines the ECDSA priviate/public key identifier for GREP11
type ecKeyIdentificationASN struct {
	KeyType asn1.ObjectIdentifier
	Curve   asn1.ObjectIdentifier
}

// ecPubKeyASN defines the ECDSA public key ASN1 encoding structure for GREP11
type ecPubKeyASN struct {
	Ident ecKeyIdentificationASN
	Point asn1.BitString
}

// DH2Int defines the Diffie-Hellman Prime and Base values extracted from the public key
type DH2Int struct {
	Prime *big.Int
	Base  *big.Int
}

// DHParam defines the Diffie-Hellman algorithm Identifier structure
type DHParam struct {
	Algorithm asn1.ObjectIdentifier
	PB        DH2Int
}

// DHPubKeyASN defines the Diffie-Hellman public key ASN1 encoding structure for GREP11
type DHPubKeyASN struct {
	Parameter DHParam
	PublicKey asn1.BitString
}

// generalKeyTypeASN is used to identify the public key ASN1 encoding structure for GREP11
type pubKeyTypeASN struct {
	KeyType asn1.ObjectIdentifier
}

// generalPubKeyASN is used to identify the public key type
type generalPubKeyASN struct {
	OIDAlgorithm pubKeyTypeASN
}

// PKCS#1 public key
type pubKeyASN struct {
	Algorithm pubKeyTypeASN
	PublicKey asn1.BitString
}

// RSA public key
type rsaPubKeyASN struct {
	Modulus  *big.Int
	Exponent int
}

func init() {
	proto.RegisterType((*pb.Grep11Error)(nil), "grep11.Grep11Error")
}

// PrintAttributes prints a table of all key attribute names and their values
func PrintAttributes(attrs map[ep11.Attribute]*pb.AttributeValue) {
	var value interface{}

	for attr, v := range attrs {
		switch v.OneAttr.(type) {
		case *pb.AttributeValue_AttributeB:
			value = "x'" + strings.ToUpper(hex.EncodeToString(v.GetAttributeB())) + "'"
		case *pb.AttributeValue_AttributeI:
			value = "x'" + strconv.FormatInt(v.GetAttributeI(), 16) + "'"
			switch ep11.AttributeValueToName[attr] {
			case "CKA_KEY_TYPE":
				value = ep11.KeyTypeValueToName[ep11.KeyType(v.GetAttributeI())]
			case "CKA_KEY_GEN_MECHANISM":
				value = ep11.MechanismValueToName[ep11.Mechanism(v.GetAttributeI())]
			case "CKA_CLASS":
				value = ep11.ObjectClassValueToName[(ep11.ObjectClass(v.GetAttributeI()))]
			}
		case *pb.AttributeValue_AttributeTF:
			value = v.GetAttributeTF()
		}

		fmt.Printf("%-20s\t%v\n", attr, value)
	}
}

// AttributeMap is a map conversion helper function
func AttributeMap(attrs ep11.EP11Attributes) map[ep11.Attribute]*pb.AttributeValue {
	rc := make(map[ep11.Attribute]*pb.AttributeValue)
	for attr, val := range attrs {
		rc[attr] = AttributeValue(val)
	}

	return rc
}

// AttributeValue converts a standard Golang type into an AttributeValue structure
func AttributeValue(v interface{}) *pb.AttributeValue {
	if v == nil {
		return &pb.AttributeValue{}
	}

	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Bool:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeTF{AttributeTF: val.Bool()}}
	case reflect.String:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: []byte(val.String())}}
	case reflect.Slice:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: val.Bytes()}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeI{AttributeI: val.Int()}}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeI{AttributeI: int64(val.Uint())}}
	default:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, val)
		return &pb.AttributeValue{OneAttr: &pb.AttributeValue_AttributeB{AttributeB: buf.Bytes()}}
	}
}

// GetAttributeByteValue obtains the byte slice equivalent of an attribute struct
func GetAttributeByteValue(val interface{}) ([]byte, error) {
	if val == nil {
		return nil, fmt.Errorf("value for attribute processing is nil")
	}
	switch v := val.(type) {
	case bool:
		if v {
			return []byte{1}, nil
		} else {
			return []byte{0}, nil
		}
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, val)
		if err != nil {
			return nil, fmt.Errorf("unhandled attribute type: %s", err)
		}
		return buf.Bytes(), nil
	}
}

// Convert is a helper function for generating proper Grep11Error structures
func Convert(err error) (bool, *pb.Grep11Error) {
	if err == nil {
		return true, nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Server returned error: [%s]", err),
			Retry:  true,
		}
	}

	detail := st.Details()
	if len(detail) != 1 {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Error: [%s]", err),
			Retry:  true,
		}
	}

	err2, ok := detail[0].(*pb.Grep11Error)
	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Error [%s]: [%s]", reflect.TypeOf(detail[0]), err),
			Retry:  true,
		}
	}

	return false, err2
}

// GetNamedCurveFromOID returns an elliptic curve from the specified curve OID
func GetNamedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(OIDNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(OIDNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(OIDNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(OIDNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

// GetSignMechanismFromOID returns the signing mechanism associated with an object identifier
func GetSignMechanismFromOID(oid asn1.ObjectIdentifier) (ep11.Mechanism, error) {
	switch {
	case oid.Equal(OIDNamedCurveED25519):
		return ep11.CKM_IBM_ED25519_SHA512, nil
	case oid.Equal(OIDNamedCurveP256):
		return ep11.CKM_ECDSA, nil
	case oid.Equal(OIDNamedCurveSecp256k1):
		return ep11.CKM_ECDSA, nil
	}
	return 0, fmt.Errorf("Unexpected OID: %+v", oid)
}

// SetMechParm is a helper function that returns a properly formatted mechanism parameter for byte slice parameters
func SetMechParm(parm []byte) *pb.Mechanism_ParameterB {
	return &pb.Mechanism_ParameterB{ParameterB: parm}
}

// GetPubKey converts an ep11 SPKI structure to a golang ecdsa.PublicKey
func GetPubKey(spki []byte) (crypto.PublicKey, asn1.ObjectIdentifier, error) {
	firstDecode := &generalPubKeyASN{}
	_, err := asn1.Unmarshal(spki, firstDecode)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmarshaling public key: %s", err)
	}

	if firstDecode.OIDAlgorithm.KeyType.Equal(OIDECPublicKey) {
		decode := &ecPubKeyASN{}
		_, err := asn1.Unmarshal(spki, decode)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed unmarshaling public key: %s", err)
		}

		if decode.Ident.Curve.Equal(OIDNamedCurveED25519) {
			return ed25519.PublicKey(decode.Point.Bytes), OIDNamedCurveED25519, nil
		}

		curve := GetNamedCurveFromOID(decode.Ident.Curve)
		if curve == nil {
			return nil, nil, fmt.Errorf("Unrecognized Curve from OID %v", decode.Ident.Curve)
		}
		x, y := elliptic.Unmarshal(curve, decode.Point.Bytes)
		if x == nil {
			return nil, nil, fmt.Errorf("failed unmarshalling public key.\n%s", hex.Dump(decode.Point.Bytes))
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, asn1.ObjectIdentifier(OIDECPublicKey), nil

	} else if firstDecode.OIDAlgorithm.KeyType.Equal(OIDRSAPublicKey) {
		decode := &pubKeyASN{}
		_, err := asn1.Unmarshal(spki, decode)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed unmarshaling PKCS public key: %s", err)
		}

		key := &rsaPubKeyASN{}
		_, err = asn1.Unmarshal(decode.PublicKey.Bytes, key)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed unmarshaling RSA public key: %s", err)
		}

		return &rsa.PublicKey{N: key.Modulus, E: key.Exponent}, OIDRSAPublicKey, nil
	} else {
		return nil, nil, fmt.Errorf("Unrecognized public key type %v", firstDecode.OIDAlgorithm)
	}
}

// GetECPointFromSPKI extracts a coordinate bit array (EC point) from the public key in SPKI format
func GetECPointFromSPKI(spki []byte) ([]byte, error) {
	decode := &ecPubKeyASN{}
	_, err := asn1.Unmarshal(spki, decode)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling public key: [%s]", err)
	}
	return decode.Point.Bytes, nil
}

// Pause is a helper function that pauses test execution until the user types CTRL-c
func Pause(m chan string, sigs chan os.Signal, message string) {
	os.Stderr.WriteString("\n" + message + "\n")
loop:
	for {
		select {
		case <-sigs:
			fmt.Println("")
			break loop
		case <-m:
		}
	}
	return
}

// ClientConfig is used to setup a gRPC connection with a remote GREP11 server
type ClientConfig struct {
	Address     string
	APIKey      string
	IAMEndpoint string
	DialOpts    []grpc.DialOption
}

// GetCryptoClient connects to the GREP11 server and returns a gRPC Crypto service client
func GetCryptoClient(config *ClientConfig) (pb.CryptoClient, *grpc.ClientConn, error) {
	conn, err := grpc.Dial(config.Address, config.DialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to server: %s", err)
	}

	return pb.NewCryptoClient(conn), conn, nil
}

// MechanismExists determines if a mechanism is supported on the remote HSM
func MechanismExists(cryptoClient pb.CryptoClient, mech ep11.Mechanism) bool {
	// Retrieve a list of all supported mechanisms
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), &pb.GetMechanismListRequest{})
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}

	idx := slices.IndexFunc(mechanismListResponse.Mechs, func(m ep11.Mechanism) bool { return m == mech })
	if idx > -1 {
		return true
	}

	return false
}

// GenerateIV generates a 16-byte initialization vector for symmetric key operations
// The remote HSM is used to generate 16 random bytes for the IV
// This function supports BlockType values of "AESBlkSize" or "DESBlkSize"
func GenerateIV(cryptoClient pb.CryptoClient, blockType BlockType) ([]byte, error) {
	rngTemplate := &pb.GenerateRandomRequest{
		Len: uint64(blockType),
	}

	// Generate 16 bytes of random data for the initialization vector
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		return nil, err
	}

	return rng.Rnd[:blockType], nil
}
