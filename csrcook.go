package main

import "fmt"
import "strings"
import "crypto/rsa"
import "crypto/rand"
import "crypto/x509"
import "crypto/x509/pkix"
import "encoding/pem"

func main() {
	csr, key := generateKeyAndCsr(2048, map[string]string{})

	fmt.Println(csr)
	fmt.Println(key)
}

func generateKeyAndCsr(bitsize int, subjectFields map[string]string) (csr_str string, key_str string) {
	key, error := rsa.GenerateKey(rand.Reader, bitsize)

	if error != nil {
		fmt.Println("Error while generating RSA keypair")
		fmt.Println(error)
	}

	tpl := prepareRequestTemplate(subjectFields)

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

	return csr_str, key_str
}

func prepareRequestTemplate(subjectFields map[string]string) *x509.CertificateRequest {
	tpl := new(x509.CertificateRequest)
	subject := new(pkix.Name)

	if subjectFields["C"] != "" {
		subject.Country = []string{subjectFields["C"]}
	}
	if subjectFields["O"] != "" {
		subject.Organization = []string{subjectFields["O"]}
	}
	if subjectFields["OU"] != "" {
		subject.OrganizationalUnit = []string{subjectFields["OU"]}
	}
	if subjectFields["ST"] != "" {
		subject.Province = []string{subjectFields["ST"]}
	}
	if subjectFields["L"] != "" {
		subject.Locality = []string{subjectFields["L"]}
	}
	if subjectFields["CN"] != "" {
		subject.CommonName = subjectFields["CN"]
	}

	tpl.Subject = *subject

	return tpl
}
