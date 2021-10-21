package main

import "flag"
import "fmt"
import "strings"
import "strconv"
import "crypto/rsa"
import "crypto/rand"
import "crypto/x509"
import "crypto/x509/pkix"
import "encoding/pem"
import "net/http"
import "net/url"
import "log"

func main() {
	var port = flag.Int("p", 8080, "port to listen on")
	flag.Parse()

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)
	http.HandleFunc("/generate", generateHandler)

	fmt.Printf("Listening on port %v ...\n", *port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(*port), nil))
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	cn := r.Form["CN"][0]
	fields := map[string]string{}

	size, fields, _ := extractFields(r.Form)
	csr, key := generateKeyAndCsr(size, fields)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+cn+".pem\"")

	fmt.Fprintf(w, "%s", csr+key)
}

func extractFields(f url.Values) (int, map[string]string, error) {
	var bitsize int
	fields := map[string]string{}

	if f["bitsize"] != nil {
		str_bitsize := f["bitsize"][0]
		size, err := strconv.Atoi(str_bitsize)
		if err != nil {
			bitsize = 1024
		} else {
			bitsize = size
		}

	} else {
		bitsize = 1024
	}

	if f["C"][0] != "" {
		fields["C"] = f["C"][0]
	}
	if f["CN"][0] != "" {
		fields["CN"] = f["CN"][0]
	}
	if f["O"][0] != "" {
		fields["O"] = f["O"][0]
	}
	if f["OU"][0] != "" {
		fields["OU"] = f["OU"][0]
	}
	if f["L"][0] != "" {
		fields["L"] = f["L"][0]
	}
	if f["ST"][0] != "" {
		fields["ST"] = f["ST"][0]
	}

	return bitsize, fields, nil
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
