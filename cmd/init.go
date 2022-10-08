package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	//port     = ":9080"
	kRB5CONF = `[libdefaults]
	  default_realm = AHMAD.IO
	  dns_lookup_realm = false
	  dns_lookup_kdc = false
	  ticket_lifetime = 24h
	  forwardable = yes
	  default_tkt_enctypes = aes256-cts-hmac-sha1-96
	  default_tgs_enctypes = aes256-cts-hmac-sha1-96
	[realms]
	AHMAD.IO = {
	  kdc = krb5.ahmad.io:88
	  admin_server = krb5.ahmad.io:749
	  default_domain = AHMAD.IO
	 }
	[domain_realm]
	 .test.gokrb5 = AHMAD.IO
	 test.gokrb5 = AHMAD.IO
	 `
)

const (
	port = ":3000"
)

func Run() {

	mux := chi.NewRouter()
	mux.Use(middleware.Logger)

	//defer profile.Start(profile.TraceProfile).Stop()
	// Create logger
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load the service's keytab
	kt, err := keytab.Load("/app/kerb5.keytab")
	if err != nil {
		log.Println(err)
	}
	// Create the application's specific handler
	th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper

	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.KeytabPrincipal("http/")))
	err = http.ListenAndServe(port, mux)
	if err != nil {
		fmt.Println(err)
	}
}

// Simple application specific handler
func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprintf(w,
		`<html>
<h1>GOKRB5 Handler</h1>
<ul>
<li>Authenticed user: %s</li>
<li>User's realm: %s</li>
<li>Authn time: %v</li>
<li>Session ID: %s</li>
<ul>
</html>`,
		creds.UserName(),
		creds.Domain(),
		creds.AuthTime(),
		creds.SessionID(),
	)
	return
}
