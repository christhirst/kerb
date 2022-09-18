package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/gorilla/sessions"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
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
	//l := log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)

	//defer profile.Start(profile.TraceProfile).Stop()
	// Load the keytab

	kt, err := keytab.Load("./krb5.keytab")
	fmt.Println(err)
	s := httpServer()
	defer s.Close()
	c, _ := config.NewFromString(kRB5CONF)
	c.LibDefaults.NoAddresses = true
	cl := client.NewWithKeytab("host/client1.ahmad.io", "AHMAD.IO", kt, c)
	httpRequest(s.URL, cl)
	/* th := http.HandlerFunc(testAppHandler)

	// Set up handler mappings wrapping in the SPNEGOKRB5Authenticate handler wrapper
	mux := http.NewServeMux()
	mux.Handle("/", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l), service.SessionManager(NewSessionMgr("gokrb5"))))

	// Start up the web server
	log.Fatal(http.ListenAndServe(port, mux)) */
}

func httpRequest(url string, cl *client.Client) {
	l := log.New(os.Stderr, "GOKRB5 Client: ", log.Ldate|log.Ltime|log.Lshortfile)

	err := cl.Login()
	if err != nil {
		l.Printf("Error on AS_REQ: %v\n", err)
	}
	r, _ := http.NewRequest("GET", url, nil)
	err = spnego.SetSPNEGOHeader(cl, r, "HTTP/client1.ahmad.io")
	if err != nil {
		l.Printf("Error setting client SPNEGO header: %v", err)
	}
	/*
		httpResp, err := http.DefaultClient.Do(r)
		if err != nil {
			l.Printf("Request error: %v\n", err)
		}
		fmt.Fprintf(os.Stdout, "Response Code: %v\n", httpResp.StatusCode)
		content, _ := io.ReadAll(httpResp.Body)
		fmt.Fprintf(os.Stdout, "Response Body:\n%s\n", content) */
}

func httpServer() *httptest.Server {
	l := log.New(os.Stderr, "GOKRB5 Service Tests: ", log.Ldate|log.Ltime|log.Lshortfile)
	kt, err := keytab.Load("./krb5.keytab")
	fmt.Println(err)
	th := http.HandlerFunc(testAppHandler)
	s := httptest.NewServer(spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	return s
}

func testAppHandler(w http.ResponseWriter, r *http.Request) {
	creds := goidentity.FromHTTPRequestContext(r)
	fmt.Fprint(w, "<html>\n<p><h1>TEST.GOKRB5 Handler</h1></p>\n")
	if creds != nil && creds.Authenticated() {
		fmt.Fprintf(w, "<ul><li>Authenticed user: %s</li>\n", creds.UserName())
		fmt.Fprintf(w, "<li>User's realm: %s</li></ul>\n", creds.Domain())
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Authentication failed")
	}
	fmt.Fprint(w, "</html>")
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
