package main

import "fmt"
import "strings"
import "crypto/rsa"
import "crypto/rand"
import "crypto/x509"
import "encoding/pem"

func main() {
	csr, key := generateKeyAndCsr()
	fmt.Println(csr)
	fmt.Println(key)
}

func generateKeyAndCsr() (csr_str string, key_str string) {
	fmt.Println("Generating RSA keypair...")

	key, error := rsa.GenerateKey(rand.Reader, 2048)
	if error != nil {
		fmt.Println("Error while generating RSA keypair")
		fmt.Println(error)
	}

	tpl := new(x509.CertificateRequest)

	csr, error := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if error != nil {
		fmt.Println("Error while generating certificate request")
		fmt.Println(error)
	}

	csr_block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	marshalled_key := x509.MarshalPKCS1PrivateKey(key)

	pkey_block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: marshalled_key,
	}

	encoded_csr := new(strings.Builder)
	encoded_key := new(strings.Builder)

	pem.Encode(encoded_csr, csr_block)
	pem.Encode(encoded_key, pkey_block)

	csr_str = encoded_csr.String()
	key_str = encoded_key.String()
	return
}
