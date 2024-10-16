/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/ep11"
	pb "github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/grpc"
	"github.com/IBM-Cloud/hpcs-grep11-go/v2/pkg/util"
)

// Example_tls tests TLS communication between a client and server using a certificate and private key that are dynamically generated
func Example_tls() {
	cryptoClient, conn, err := util.GetCryptoClient(&ClientConfig)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	privKeyBlob, spki, err := generateECDSAKeyPair(cryptoClient)
	if err != nil {
		panic(fmt.Errorf("Failed to generate ECDSA key pair: %s", err))
	}

	// Create signer and raw certificate to build up TLS certificate
	priv, err := util.NewEP11Signer(cryptoClient, privKeyBlob, spki)
	if err != nil {
		panic(fmt.Errorf("NewEP11Signer error: %s\n", err))
	}
	certDER, err := createECDSASelfSignedCert(priv, "localhost")
	if err != nil {
		panic(fmt.Errorf("createECDSASelfSignedCert error: %s\n", err))
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Create and start server thread
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
	}
	lis, err := tls.Listen("tcp", ":0", tlsCfg)
	if err != nil {
		panic(fmt.Errorf("Failed to listen: %s\n", err))
	}
	httpServer := CreateServer(lis.Addr().String())

	defer httpServer.Close()
	go func() {
		httpServer.Serve(lis)
	}()

	// Create TLS client
	client := newHTTPTestClient(certDER)
	strResp, err := ping(client, lis.Addr().String())
	if err != nil {
		panic(fmt.Errorf("Ping failed: %s\n", err))
	} else {
		fmt.Printf("Response data from https server: [%s]\n", strResp)
	}

	// Output:
	// Response data from https server: [Hello]
}

// generateECDSAKeyPair generates a 256-bit ECDSA key pair
func generateECDSAKeyPair(cryptoClient pb.CryptoClient) (*pb.KeyBlob, *pb.KeyBlob, error) {
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to encode parameter OID: %s", err)
	}
	publicKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_EC_PARAMS:   ecParameters,
		ep11.CKA_VERIFY:      true,
		ep11.CKA_EXTRACTABLE: false,
	}
	privateKeyECTemplate := ep11.EP11Attributes{
		ep11.CKA_SIGN:        true,
		ep11.CKA_EXTRACTABLE: false,
	}
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  util.AttributeMap(publicKeyECTemplate),
		PrivKeyTemplate: util.AttributeMap(privateKeyECTemplate),
	}
	var ecKeypairResponse *pb.GenerateKeyPairResponse
	ecKeypairResponse, err = cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("Generate ECDSA key pair error: %s", err)
	}
	return ecKeypairResponse.PrivKey, ecKeypairResponse.PubKey, nil
}

func createECDSASelfSignedCert(privKey *util.EP11PrivateKey, commonName string) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),
		DNSNames:  []string{"localhost"},
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	return certDERBytes, nil
}

// StartServer starts an https server
func CreateServer(listenAddr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hello"))
	})
	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
	return httpServer
}

func newHTTPTestClient(caCertDER []byte) *http.Client {
	x509Cert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		fmt.Printf("x509.ParseCertificate failed: %s\n", err)
		return nil
	}
	clientCertPool := x509.NewCertPool()
	// Append the client certificates from the CA
	clientCertPool.AddCert(x509Cert)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "localhost",
				RootCAs:    clientCertPool,
			},
		},
	}

	return httpClient
}

func ping(client *http.Client, serverAddr string) (string, error) {
	// serverAddr in format of a.b.c.d:port in ipv4 or [::]:port in ipv6
	var serverPort string
	id := strings.LastIndex(serverAddr, ":")
	if id != -1 {
		serverPort = serverAddr[id:]
	} else {
		serverPort = serverAddr
	}
	fullAddr := "https://localhost" + serverPort

	resp, err := client.Get(fullAddr)
	if err != nil {
		return "", fmt.Errorf("Http client get failed: %s", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("ioutil.ReadAll failed: %s", err)
	}
	return string(data), nil
}
