package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

const (
	port     = ":9080"
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

func Run() {

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "DNT", "Host", "Origin", "Pragma", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	l := log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)
	// Load the keytab
	kt, err := keytab.Load("./krb5.keytab")
	if err != nil {
		l.Println("could not load client keytab: %a", err)
	}
	// Load the client krb5 config
	conf, err := config.NewConfigFromString(kRB5CONF)
	if err != nil {
		l.Println("could not load krb5.conf: %a", err)
	}
	// Create the client with the keytab
	cl := client.NewClientWithKeytab("testuser2", "TEST.GOKRB5", kt, conf, client.Logger(l), client.DisablePAFXFAST(true))
	// Log in the client
	err = cl.Login()
	if err != nil {
		l.Println("could not login client: %a", cl)
	}

	h := http.HandlerFunc(testAppHandler)
	r.Handle("/", spnego.SPNEGOKRB5Authenticate(h, kt, service.Logger(l), service.KeytabPrincipal("pn")))
	oo := http.ListenAndServe(":3000", r)
	l.Println(oo)

}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	ctx := r.Context()
	creds := ctx.Value(spnego.CTXKeyCredentials).(goidentity.Identity)
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
