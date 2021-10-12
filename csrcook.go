package main

import "fmt"
import "os"
import "crypto/rsa"
import "crypto/rand"
import "crypto/x509"
import "encoding/pem"

func main() {
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

	pem.Encode(os.Stdout, csr_block)
	pem.Encode(os.Stdout, pkey_block)
}
