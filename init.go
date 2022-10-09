package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	port = ":3000"
)

type ConnKerb struct {
	kt  *keytab.Keytab
	l   *log.Logger
	spn string
}

/* func Runs() {
	th := http.HandlerFunc(testAppHandler)
	mm := ConnKerb{spn: "http/"}
	mm.InitKerb()
	mux := chi.NewRouter()
	mux.Use(middleware.Logger)
	mux.Handle("/", mm.SpHandler(th, mm.kt, mm.l, ""))
	err := http.ListenAndServe(port, mux)
	if err != nil {
		fmt.Println(err)
	}

} */

func (t *ConnKerb) InitKerb() {
	var err error
	t.kt, err = keytab.Load("/app/kerb5.keytab")
	if err != nil {
		log.Println(err)
	}
	//defer profile.Start(profile.TraceProfile).Stop()
	// Create logger
	t.l = log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

}

func userdata(userName string, authTime time.Time) {
	fmt.Println(userName, authTime)
}

func (t *ConnKerb) SpHandler(h http.Handler, kt *keytab.Keytab, l *log.Logger, spn string) http.Handler {
	if true {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("vv")
			uu := spnego.SPNEGOKRB5Authenticate(h, kt, service.Logger(l), service.KeytabPrincipal(spn))
			uu.ServeHTTP(w, r) // call original
		})
	} else {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("ee")
			spnego.SPNEGOKRB5Authenticate(h, kt, service.Logger(l), service.KeytabPrincipal(spn))
			//h.ServeHTTP(w, r) // call original
		})
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
	userdata(creds.UserName(), creds.AuthTime())
}
