package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
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
	//defer profile.Start(profile.TraceProfile).Stop()
	// Create logger
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Load the service's keytab
	kt, err := keytab.Load("/path/to/file.keytab")
	if err != nil {
		log.Println(err)
	}
	// Create the application's specific handler
	th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper
	mux := http.NewServeMux()
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.KeytabPrincipal("http/")))

	// Start up the web server
	log.Fatal(http.ListenAndServe(port, mux))
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

type SessionMgr struct {
	skey       []byte
	store      sessions.Store
	cookieName string
}

func NewSessionMgr(cookieName string) SessionMgr {
	skey := []byte("thisistestsecret") // Best practice is to load this key from a secure location.
	return SessionMgr{
		skey:       skey,
		store:      sessions.NewCookieStore(skey),
		cookieName: cookieName,
	}
}

func (smgr SessionMgr) Get(r *http.Request, k string) ([]byte, error) {
	s, err := smgr.store.Get(r, smgr.cookieName)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("nil session")
	}
	b, ok := s.Values[k].([]byte)
	if !ok {
		return nil, fmt.Errorf("could not get bytes held in session at %s", k)
	}
	return b, nil
}

func (smgr SessionMgr) New(w http.ResponseWriter, r *http.Request, k string, v []byte) error {
	s, err := smgr.store.New(r, smgr.cookieName)
	if err != nil {
		return fmt.Errorf("could not get new session from session manager: %v", err)
	}
	s.Values[k] = v
	return s.Save(r, w)
}
