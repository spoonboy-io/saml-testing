package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/crewjam/saml"
	"log"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/samlsp"
)

var spRedirectBinding *samlsp.Middleware

func protected(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func home(w http.ResponseWriter, r *http.Request) {
	output := `
	<h2>SAML SSO Test - HTTP REDIRECT</h2>

	<p>Used with Insomnia to inspect the HTTP-REDIRECT mechanism by which the user is sent to the IDP</p>

	<h3>SP initiated with HTTP-REDIRECT</h3>
	<p>Visit/use this link</p>
	<a href="http://localhost:8000/redirect-binding">http://localhost:8000/redirect-binding</a>
`
	w.Header().Add("content-type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, output)
}

func errFatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("certs/myservice.cert", "certs/myservice.key")
	errFatal(err)

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	errFatal(err)

	// get the test IDP meta data
	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	errFatal(err)

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	errFatal(err)

	serverURL, err := url.Parse("http://localhost:8000")
	errFatal(err)

	spRedirectBinding, _ := samlsp.New(samlsp.Options{
		URL:         *serverURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})

	spRedirectBinding.Binding = saml.HTTPRedirectBinding

	app := http.HandlerFunc(protected)

	// we test with the redirect binding at this endpoint
	http.Handle("/redirect-binding", spRedirectBinding.RequireAccount(app))
	http.Handle("/saml/", spRedirectBinding)

	http.Handle("/", http.HandlerFunc(home))

	log.Println("Redirect Test Application running on localhost:8000")
	http.ListenAndServe(":8000", nil)
}
