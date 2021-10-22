A very basic Certificate Signing Request generator, implemented as a web app
written in Go. Serves a form for entering CSR parameters and choosing private
key size. CSR and key are sent back in single .pem file.

`go build csrcook.go` and run with`./csrcook -p 3000` from anywhere, assets
embedded.

Requires Go 1.16 or newer.
