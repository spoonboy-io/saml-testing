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

var spPostBinding *samlsp.Middleware

func protected(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func home(w http.ResponseWriter, r *http.Request) {
	output := `
	<h2>SAML SSO Test - HTTP POST</h2>

	<p>Used with Insomnia to inspect the HTTP POST mechanism by which the user is sent to the IDP</p>

	<h3>SP initiated with HTTP-POST</h3>
	<p>Visit/use this link</p>
	<a href="http://localhost:8001/post-binding">http://localhost:8001/post-binding</a>
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

	serverURL, err := url.Parse("http://localhost:8001")
	errFatal(err)

	spPostBinding, _ := samlsp.New(samlsp.Options{
		URL:         *serverURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})

	spPostBinding.Binding = saml.HTTPPostBinding

	app := http.HandlerFunc(protected)

	// we test with the post-binding at this endpoint
	http.Handle("/post-binding", spPostBinding.RequireAccount(app))
	http.Handle("/saml/", spPostBinding)

	http.Handle("/", http.HandlerFunc(home))

	log.Println("Post Test Application running on localhost:8001")
	http.ListenAndServe(":8001", nil)
}
