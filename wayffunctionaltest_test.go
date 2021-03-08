package wayffunctionaltest

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lmdq"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"math/rand"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"
)

const (
	requesting = iota
	responding
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	// https://stackoverflow.com/questions/47475802/golang-301-moved-permanently-if-request-path-contains-additional-slash
	slashFix struct {
		mux http.Handler
	}

	Testparams struct {
		Idp, SP, BirkIdp, FinalIdp, Hybrid, RelayState     string
		Spmd, Idpmd, Hubidpmd, Hubspmd, Birkmd, Firstidpmd *goxml.Xp
		Cookiejar                                          map[string]map[string]*http.Cookie
		Destination                                        *url.URL
		//      Resolv                                             map[string]string
		Method                                                   string
		Initialrequest, FinalRequest                             *goxml.Xp
		Newresponse                                              *goxml.Xp
		Resp                                                     *http.Response
		Responsebody                                             []byte
		Err                                                      error
		Trace, Logxml, Encryptresponse                           bool
		Privatekey                                               string
		Privatekeypw                                             string
		Certificate                                              string
		Hashalgorithm                                            string
		Attributestmt                                            *goxml.Xp
		Hub, Birk, ConsentGiven                                  bool
		Env                                                      string
		ElementsToSign                                           []string
		Jwt2SAML, SAML2jwt, Jwt2SAMLResponse                     string
		Jwt2SAMLDoRequest, SAML2jwtDoRequest, SAML2jwtDoResponse bool
		WSFedDoRequest                                           bool
		PassedDisco, CheckRequesterID                            bool
		AsyncSLO                                                 bool
	}

	overwrites map[string]interface{}

	mod struct {
		Path, Value string
		Function    func(*goxml.Xp, mod)
	}

	mods []mod

	modsset map[string]mods
	M       map[string]interface{} // just an alias
)

var (
	mdsources = map[string]map[string]string{
		"prod": {
			"hub":         "hybrid-metadata.mddb",
			"internal":    "hybrid-metadata.mddb",
			"externalIdP": "hybrid-metadata.mddb",
			"externalSP":  "hybrid-metadata.mddb",
		},
	}

	hubMd, internalMd, externalIdPMd, externalSPMd *lmdq.MDQ
	mdMap                                          map[string]*lmdq.MDQ
	mdqMap                                         map[string]map[string]*goxml.Xp

	do           = flag.String("do", "hub", "Which tests to run")
	hub          = flag.String("hub", "wayf.wayf.dk", "the hostname for the hub server to be tested")
	hubbe        = flag.String("hubbe", "", "the hub backend server")
	ds           = flag.String("ds", "ds.wayf.dk", "the discovery server")
	testmdq      = flag.Bool("testmdq", false, "test with embedded mdq server")
	trace        = flag.Bool("trace", false, "trace the request/response flow")
	logxml       = flag.Bool("logxml", false, "dump requests/responses in xml")
	env          = flag.String("env", "prod", "which environment to test dev, hybrid, prod - if not dev")
	testcertpath = flag.String("testcertpath", "/etc/ssl/wayf/certs/wildcard.test.lan.pem", "path to the testing cert")
	insecureTLS  = true

	testSPs *goxml.Xp

	dohub, dobirk bool

	old, r, w      *os.File
	outC           = make(chan string)
	templatevalues = map[string]map[string]string{
		"prod": {
			"eptid":   "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"iss":     "123",
			"exp":     "456",
		},
	}

	stdAttributesTxt, stdAttributesJson string

	resolv map[string]string
	wg     sync.WaitGroup
	tr     *http.Transport
	client *http.Client
	path string
)

func TestMain(m *testing.M) {
	flag.Parse()
	if !strings.ContainsAny(*hub, ".") {
		*hubbe = *hub
		*hub = "wayf.wayf.dk"
	}

	path = Env("WAYF_PATH", "/opt/wayf/")

	log.Printf("hub: %q backend: %q %s\n", *hub, *hubbe, *env)

	gosaml.AuthnRequestCookie = &gosaml.Hm{180, sha256.New, []byte("abcd")}

	hubMd = &lmdq.MDQ{Path: "file:" + path + mdsources[*env]["hub"] + "?mode=ro", Table: "HYBRID_HUB"}
	internalMd = &lmdq.MDQ{Path: "file:" + path + mdsources[*env]["internal"] + "?mode=ro", Table: "HYBRID_INTERNAL"}
	externalIdPMd = &lmdq.MDQ{Path: "file:" + path + mdsources[*env]["externalIdP"] + "?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	externalSPMd = &lmdq.MDQ{Path: "file:" + path + mdsources[*env]["externalSP"] + "?mode=ro", Table: "HYBRID_EXTERNAL_SP"}
	for _, md := range []gosaml.Md{hubMd, internalMd, externalIdPMd, externalSPMd} {
		err := md.(*lmdq.MDQ).Open()
		if err != nil {
			panic(err)
		}
	}

	mdMap = map[string]*lmdq.MDQ{"hub": hubMd, "int": internalMd, "idp": externalIdPMd, "sp": externalSPMd}

	if *testmdq {
		/*
		   Internal MDQ server for being able to modify md for the hub on the fly ...
		*/
		httpMux := http.NewServeMux()
		httpMux.Handle("/MDQ/", appHandler(mdq))

		go func() {
			intf := "127.0.0.1:9999"
			log.Println("listening on ", intf)
			err := http.ListenAndServe(intf, &slashFix{httpMux})
			if err != nil {
				log.Printf("main(): %s\n", err)
			}
		}()
	}
	// need non-birk, non-request.validate and non-IDPList SPs for testing ....
	var numberOfTestSPs int
	testSPs, numberOfTestSPs, _ = internalMd.MDQFilter("/md:EntityDescriptor/md:Extensions/wayf:wayf[wayf:federation='WAYF' and not(wayf:IDPList)]/../../md:SPSSODescriptor/..")
	if numberOfTestSPs == 0 {
		log.Fatal("No testSP candidates")
	}

	resolv = map[string]string{"wayf.wayf.dk:443": *hub + ":443", "birk.wayf.dk:443": *hub + ":443", "krib.wayf.dk:443": *hub + ":443", "ds.wayf.dk:443": *ds + ":443"}

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, resolv[addr], 3*time.Second)
		},
		DisableCompression: true,
		/*
		   DialContext: (&net.Dialer{
		       Timeout: 3 * time.Second,
		   }).DialContext,
		*/
	}

	client = &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	*do = "hub"
	dohub = true
	r := m.Run()
	//os.Exit(r)

	*do = "birk"
	dohub = false
	dobirk = true
	r += m.Run()
	os.Exit(r)

}

func Env(name, defaultvalue string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return defaultvalue
}

func (h *slashFix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	h.mux.ServeHTTP(w, r)
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Printf("in: %s %s %s %+v", r.RemoteAddr, r.Method, r.Host, r.URL)
	//starttime := time.Now()
	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		if err.Error() == "401" {
			status = 401
		}
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	//log.Printf("%s %s %s %+v %1.3f %d %s", r.RemoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)
}

// MDQWeb - thin MDQ web layer on top of lmdq
func mdq(w http.ResponseWriter, r *http.Request) (err error) {
	var rawPath string
	if rawPath = r.URL.RawPath; rawPath == "" {
		rawPath = r.URL.Path
	}
	path := strings.SplitN(rawPath, "/", 4)[2:]
	ent, _ := url.PathUnescape(path[1])
	xp, ok := mdqMap[path[0]][ent]
	if !ok {
		xp, err = mdMap[path[0]].MDQ(ent)
		if err != nil {
			return
		}
	}
	xml := xp.Dump()
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(xml)))
	w.Write([]byte(xml))
	//log.Print(xp.PP())
	return
}

func (tp *Testparams) logxml(x interface{}) {
	if tp.Logxml {
		var xml *goxml.Xp
		switch i := x.(type) {
		case *url.URL:
			query := i.Query()
			req, _ := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
			xml = goxml.NewXp(gosaml.Inflate(req))
		case *goxml.Xp:
			xml = i
		}
		log.Println(xml.PP())
	}
}

func stdoutstart() {
	old = os.Stdout // keep backup of the real stdout
	r, w, _ = os.Pipe()
	os.Stdout = w
	outC = make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()
}

func stdoutend(t *testing.T, expected string, re ...string) {
	// back to normal state
	var b bytes.Buffer
	w.Close()
	os.Stdout = old // restoring the real stdout
	got := <-outC

	tmpl := template.Must(template.New("expected").Parse(expected))
	_ = tmpl.Execute(&b, templatevalues[*env])
	expected = b.String()
	if expected == "" {
		//      t.Errorf("unexpected empty expected string\n")
	}
	if len(re) != 0 {
		repl := "$1"
		if len(re) > 1 {
			repl = re[1]
		}
		got = regexp.MustCompile(re[0]).ReplaceAllString(got, repl)
	}
	if expected != got {
		t.Errorf("\nexpected:\n%s\ngot:\n%s\n%s\n", expected, got, diff(expected, got))
	}
}

func diff(str1, str2 string) (str string) {
	slice1 := strings.Split(str1, "\n")
	slice2 := strings.Split(str2, "\n")
	for i, line1 := range slice1 {
	    line2 := ""
	    if len(slice2) > i {
	        line2 = slice2[i]
	    }
		if line1 != line2 {
			return fmt.Sprintf("\ndiff:\n%s\n%s\n", line1, line2)
		}
	}
	return
}

func Newtp(overwrite *overwrites) (tp *Testparams) {
	tp = new(Testparams)
	tp.Privatekeypw = os.Getenv("PW")
	if tp.Privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp.Method = "GET"
	tp.Env = *env
	tp.Hub = dohub
	tp.Birk = dobirk
	tp.Trace = *trace
	tp.Logxml = *logxml
	tp.Hashalgorithm = "sha256"
	tp.Hybrid = "wayf.wayf.dk"
	tp.ElementsToSign = []string{"saml:Assertion[1]"}
	tp.SAML2jwt = "https://wayf.wayf.dk/saml2jwt"
	tp.Jwt2SAML = "https://wayf.wayf.dk/jwt2saml"
	tp.Idp = "https://this.is.not.a.valid.idp"
	SP := "https://wayfsp.wayf.dk"
	tp.Spmd, _ = internalMd.MDQ(SP)

	tp.Cookiejar = make(map[string]map[string]*http.Cookie)
	tp.Cookiejar["wayf.dk"] = make(map[string]*http.Cookie)
	tp.Cookiejar["wayf.dk"]["wayfid"] = &http.Cookie{Name: "wayfid", Value: *hubbe}
	//	tp.Cookiejar["wayf.dk"]["debug"] = &http.Cookie{Name: "debug", Value: "trace=1"}

	if overwrite != nil { // overwrite default values with test specific values while it still matters
		for k, v := range *overwrite {
			reflect.ValueOf(tp).Elem().FieldByName(k).Set(reflect.ValueOf(v))
		}
	}

    root := tp.Spmd.DocGetRootElement()
	tp.Spmd = goxml.NewXpFromNode(root) // ordinary CpXp shares the DOM, and thats what we want to be able to modify

	tp.FinalIdp = tp.Idp
	tp.SP = tp.Spmd.Query1(nil, "@entityID")
	tp.Hubidpmd, _ = hubMd.MDQ("https://wayf.wayf.dk")
	tp.Hubspmd = tp.Hubidpmd
	tp.Idpmd, _ = internalMd.MDQ(tp.Idp)
	if tp.Idpmd == nil {
		tp.Idpmd, _ = externalIdPMd.MDQ(tp.Idp) // might be an external
	}
	tp.Birkmd, _ = externalIdPMd.MDQ(tp.Idp)

	switch *do {
	case "hub":
		tp.Firstidpmd = tp.Hubidpmd
	case "birk":
		tp.Firstidpmd = tp.Birkmd
	}
	tp.Attributestmt = newAttributeStatement(testAttributes)

	pk, cert, _ := gosaml.GetPrivateKey(tp.Idpmd, "md:IDPSSODescriptor"+gosaml.SigningCertQuery)
	tp.Privatekey, tp.Certificate = string(pk), cert

	// due to dependencies on tp.Idpmd we need to overwrite again for specific keys
	// to be able to test for "wrong" keys
	if overwrite != nil {
		lateOverWrites := []string{"Privatekey", "Certificate"}
		for _, k := range lateOverWrites {
			if v, ok := (*overwrite)[k]; ok {
				reflect.ValueOf(tp).Elem().FieldByName(k).Set(reflect.ValueOf(v))
			}
		}
	}
	return
}

func newAttributeStatement(attrs map[string][]string) (ats *goxml.Xp) {
	template := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
<saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></saml:NameID>
</saml:Subject>
<saml:AuthnStatement>
    <saml:AuthnContext>
        <saml:AuthnContextClassRef>
            urn:oasis:names:tc:SAML:2.0:ac:classes:Password
        </saml:AuthnContextClassRef>
    </saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement/>
</saml:Assertion>`

	ats = goxml.NewXpFromString(template)
	ats.QueryDashP(nil, "./saml:Subject/saml:NameID", gosaml.ID(), nil)
	attributeStmt := ats.Query(nil, "./saml:AttributeStatement")[0]
	i := 1
	for attr, attrvals := range attrs {
		attrelement := ats.QueryDashP(attributeStmt, `saml:Attribute[`+strconv.Itoa(i)+`]`, "", nil)
		ats.QueryDashP(attrelement, "@Name", attr, nil)
		ats.QueryDashP(attrelement, "@NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", nil)
		j := 1
		for _, attrval := range attrvals {
			attrvalelement := ats.QueryDashP(attrelement, `saml:AttributeValue[`+strconv.Itoa(j)+`]`, attrval, nil)
			ats.QueryDashP(attrvalelement, "@xsi:type", "xs:string", nil)
			j = j + 1
		}
		i = i + 1
	}
	return
}

func SAML2jwtDo(service string, v url.Values) (resp *http.Response, err error) {
	body := strings.NewReader(v.Encode())
	req, _ := http.NewRequest("POST", service, body)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	return
}

func (tp *Testparams) SAML2jwtRequest() (u *url.URL) {
	acs := []string{tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL")}
	issuer := []string{tp.Initialrequest.Query1(nil, "saml:Issuer")}
	resp, _ := SAML2jwtDo(tp.SAML2jwt, url.Values{"acs": acs, "issuer": issuer})
	location := resp.Header.Get("location")
	u, _ = url.Parse(location)
	return
}

func (tp *Testparams) SAML2jwtResponse() (attrs map[string]interface{}) {
	data := url.Values{
		"SAMLResponse": []string{base64.StdEncoding.EncodeToString([]byte(tp.Newresponse.Dump()))},
		"RelayState":   []string{tp.RelayState},
	}
	acs := tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL")
	issuer := tp.Initialrequest.Query1(nil, "saml:Issuer")
	data.Set("acs", acs)
	data.Set("issuer", issuer)
	resp, _ := SAML2jwtDo(tp.SAML2jwt, data)
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	headerPayloadSignature := strings.SplitN(string(body), ".", 3)
	payload, _ := base64.RawURLEncoding.DecodeString(headerPayloadSignature[1])
	json.Unmarshal(payload, &attrs)
	for _, v := range []string{"iat", "exp", "nbf"} { // delete timestamps - changes all the time ..
		attrs[v] = "1234"
	}
	return
}

func (tp *Testparams) Jwt2SAMLDo(v url.Values) (err error) {
	req, err := http.NewRequest("GET", tp.Jwt2SAML+"?"+v.Encode(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf(string(body))
	}
	if len(v["preflight"]) == 0 {
		tp.Newresponse, tp.RelayState, _ = gosaml.HTML2SAMLResponse(body)
	} else {
		tp.Jwt2SAMLResponse = string(body)
	}
	return
}

func (tp *Testparams) WSFedRequest() (u *url.URL) {
	u, _ = url.Parse(tp.Initialrequest.Query1(nil, "@Destination"))
	q := u.Query()
	q.Add("wa", "wsignin1.0")
	q.Add("wctx", tp.RelayState)
	q.Add("wtrealm", tp.Initialrequest.Query1(nil, "saml:Issuer"))
	q.Add("wreply", tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL"))
	u.RawQuery = q.Encode()
	return
}

func initialRequest(m modsset, overwrite interface{}) (tp *Testparams, u *url.URL, body string) {
	switch t := overwrite.(type) {
	case *overwrites:
		tp = Newtp(t)
	case *Testparams:
		tp = t
	case nil:
		tp = Newtp(nil)
	}

	tp.Initialrequest, _, _ = gosaml.NewAuthnRequest(nil, tp.Spmd, tp.Firstidpmd, "", []string{}, "", false, 0, 0)

	if tp.SAML2jwtDoRequest {
		u = tp.SAML2jwtRequest()
	} else if tp.WSFedDoRequest {
		u = tp.WSFedRequest()
	} else {
		ApplyModsXp(tp.Attributestmt, m["attributemods"])
		ApplyModsXp(tp.Initialrequest, m["requestmods"])
		u, _ = gosaml.SAMLRequest2URL(tp.Initialrequest, "", "", "", "")
		if tp.Method == "POST" {
			body = url.Values{
				"SAMLRequest": []string{base64.StdEncoding.EncodeToString([]byte(tp.Initialrequest.Dump()))},
				"RelayState":  []string{tp.RelayState},
			}.Encode()
			u.RawQuery = ""
		}
		applyModsQuery(u, m["querymods"])
		applyModsCookie(tp, m["cookiemods"])
	}
	if *testmdq {
        mdqMap = map[string]map[string]*goxml.Xp{"int": {}, "idp": {}}
    		if len(m["mdspmods"]) > 0 {
			ApplyModsXp(tp.Spmd, m["mdspmods"])
			mdqMap["int"][tp.SP] = tp.Spmd
			mdqMap["int"][gosaml.IDHash(tp.SP)] = tp.Spmd
		}
		if len(m["mdidpmods"]) > 0 {
			ApplyModsXp(tp.Idpmd, m["mdidpmods"])
			mdqMap["int"][tp.Idp] = tp.Idpmd
			mdqMap["int"][gosaml.IDHash(tp.Idp)] = tp.Idpmd
		}
		if len(m["mdexternalidpmods"]) > 0 {
			ApplyModsXp(tp.Birkmd, m["mdexternalidpmods"])
			mdqMap["idp"][tp.Idp] = tp.Birkmd
			mdqMap["idp"][gosaml.IDHash(tp.Idp)] = tp.Birkmd
		}
	}
	return
}

// Does what the browser does follow redirects and POSTs and displays errors
func browse(m modsset, overwrite interface{}) (tp *Testparams) {
	var data url.Values

	tp, u, body := initialRequest(m, overwrite)
	// when to stop
	finalDestination, _ := url.Parse(tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL"))
	finalIdp, _ := url.Parse(tp.FinalIdp)
	redirects := 7
	var samlresponse *goxml.Xp

	for { // Sending requests upstream
		tp.logxml(u)
		tp.Resp, tp.Responsebody, samlresponse, tp.Err = tp.sendRequest(u, body)
		if tp.Err != nil {
			//log.Println(tp.Err)
			fmt.Println(tp.Err)
			return nil
			//log.Panic(tp.Err)
		}
		if u, _ = tp.Resp.Location(); u != nil { // Redirecting - we don't care about the StatusCode - Location means redirect
			query := u.Query()
			// we got to a discoveryservice - choose our testidp
			if len(query["return"]) > 0 && len(query["returnIDParam"]) > 0 {
				u, _ = url.Parse(query["return"][0])
				q := u.Query()
				q.Set(query["returnIDParam"][0], tp.Idp)
				u.RawQuery = q.Encode()
				tp.PassedDisco = true
			}
			if u.Host == finalIdp.Host {
				break
			}
		}
		redirects--
		if redirects == 0 { // if we go wild ...
			return
		}
	}

	err := tp.newresponse(u, m["presigningresponsemods"])
	if err != nil {
		return nil
	}
	tp.Method = "POST"

	for { // Sending responses downstream
		tp.logxml(tp.Newresponse)
		u = tp.Destination // fall back if no @Destination - taken from form action
		acs := tp.Newresponse.Query1(nil, "@Destination")
		if acs != "" {
			u, _ = url.Parse(acs)
		}
		if u.Host == finalDestination.Host { // why down her - SAML2jwt needs data to be set
			break
		}
		if u.Host == tp.Hybrid { // only change the response to the place we are actually testing (wayf|krib).wayf.dk
			ApplyModsXp(tp.Newresponse, m["responsemods"])
		}
		data = url.Values{
			"SAMLResponse": []string{base64.StdEncoding.EncodeToString([]byte(tp.Newresponse.Dump()))},
			"RelayState":   []string{tp.RelayState},
		}
		tp.Resp, tp.Responsebody, samlresponse, tp.Err = tp.sendRequest(u, data.Encode())
		if tp.Err != nil {
			fmt.Println(tp.Err)
			return nil
			//log.Panic(tp.Err)
		}
		if tp.Resp.StatusCode == 500 {
			break
		} else {
			tp.Newresponse = samlresponse
		}
		redirects--
		if redirects == 0 { // if we go wild ...
			return
		}
	}
	// back to the SP or we got an error
	if tp.Resp.StatusCode == 500 {
		error := string(tp.Responsebody)
		//error = regexp.MustCompile("^\\d* ").ReplaceAllString(error, "")
		fmt.Println(strings.Trim(error, "\n "))
		return nil
	} else {
		tp.ConsentGiven = strings.Contains(string(tp.Responsebody), `,"BypassConfirmation":false`)
		tp.logxml(tp.Newresponse)
		if tp.SAML2jwtDoResponse {
			attrs := tp.SAML2jwtResponse()
			PP(attrs)
		} else {
			err := ValidateSignature(tp.Firstidpmd, tp.Newresponse)
			if err != nil {
				fmt.Printf("signature errors: %s\n", err)
			}
		}
	}

	if tp.Trace {
		log.Println()
	}
	tp.Resp = nil // can't jsonify tp.Resp
	return
}

func browseSLO(tp *Testparams) {
	type sloRec struct {
		entityid string
		role     uint8
	}

	sloRecs := map[string]sloRec{
		"https://this.is.not.a.valid.external.idp/SLO": {"https://this.is.not.a.valid.external.idp", gosaml.SPRole},
		"https://this.is.not.a.valid.idp/SLO":          {"https://this.is.not.a.valid.idp", gosaml.SPRole},
		"https://wayfsp.wayf.dk/SLO":                   {"https://wayfsp.wayf.dk", gosaml.IDPRole},
		"https://wayfsp2.wayf.dk/SLO":                  {"https://wayfsp2.wayf.dk", gosaml.IDPRole},
	}

	context := tp.Newresponse.Query(nil, "/samlp:Response/saml:Assertion")[0]
	sloinfo := gosaml.NewSLOInfo(tp.Newresponse, context, tp.Spmd.Query1(nil, "@entityID"), false, gosaml.SPRole, "")
	slo, _, _ := gosaml.NewLogoutRequest(tp.Hubidpmd, sloinfo, tp.Spmd.Query1(nil, "@entityID"), tp.AsyncSLO)
	slo.QueryDashP(nil, "@ID", gosaml.ID(), nil)
	finalIssuer, _ := url.Parse(slo.Query1(nil, "./saml:Issuer"))
	tp.logxml(slo)
	tp.Method = "GET"

	for {
		var saml *goxml.Xp
		u, _ := gosaml.SAMLRequest2URL(slo, "", tp.Privatekey, tp.Privatekeypw, "")
		tp.Resp, tp.Responsebody, saml, tp.Err = tp.sendRequest(u, "")
		if tp.Err != nil {
			fmt.Println(tp.Err)
			return
			//log.Panic(tp.Err)
		}
		tp.logxml(saml)
		dest := saml.Query1(nil, "@Destination")
		u, _ = url.Parse(dest)
		fmt.Println("logout", u.Host)
		if u.Host == finalIssuer.Host {
			return
		} else {
			spMd := tp.Hubspmd
			if u.Host == "this.is.not.a.valid.external.idp" { // must send response to krib location
				spMd, _ = externalSPMd.MDQ(tp.SP)
			}
			slo, _, _ = gosaml.NewLogoutResponse(sloRecs[dest].entityid, spMd, saml.Query1(nil, "@ID"), sloRecs[dest].role)
			tp.logxml(slo)
		}
	}
}

// SendRequest sends a http request - GET or POST using the supplied url, server, method and cookies
// It updates the cookies and returns a http.Response and a posssible response body and error
// The server parameter contains the dns name of the actual server, which should respond to the host part of the url
func (tp *Testparams) sendRequest(url *url.URL, body string) (resp *http.Response, responsebody []byte, samlresponse *goxml.Xp, err error) {
	var payload io.Reader
	if tp.Method == "POST" {
		payload = strings.NewReader(body)
	}

	host := url.Host
	cookiedomain := "wayf.dk"
	req, err := http.NewRequest(tp.Method, url.String(), payload)

	for _, cookie := range tp.Cookiejar[cookiedomain] {
		req.AddCookie(cookie)
	}

	if tp.Method == "POST" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(body)))
	}

	req.Header.Add("Host", host)

	resp, err = client.Do(req)
	if err != nil && !strings.HasSuffix(err.Error(), "redirect-not-allowed") {
		// we need to do the redirect ourselves so a self inflicted redirect "error" is not an error
		// debug.PrintStack()
		if strings.HasSuffix(err.Error(), "connect: connection refused") {
		    PP(err)
		    log.Panic(err)
		}
		return nil, nil, nil, err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Expires.Unix() == 0 {
			delete(tp.Cookiejar[cookiedomain], cookie.Name)
		} else {
			tp.Cookiejar[cookiedomain][cookie.Name] = cookie
		}
	}

	responsebody, err = ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode == 500 {
		return nil, nil, nil, fmt.Errorf(strings.Trim(string(responsebody), " \n\t"))
	}

	// We didn't get a Location: header - we are POST'ing a SAMLResponse
	var loc string
	tp.Destination, _ = resp.Location()
	if tp.Destination == nil {
		samlresponse, _, tp.Destination = gosaml.HTML2SAMLResponse(responsebody)
	} else {
		q := tp.Destination.Query()
		req, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest") + q.Get("SAMLResponse")) // never both at the same time
		samlresponse = goxml.NewXp(gosaml.Inflate(req))
	}

	if tp.Trace {
		loc = tp.Destination.Host + tp.Destination.Path
		log.Printf("%-4s %-70s %s %-15s %s\n", req.Method, host+req.URL.Path, resp.Proto, resp.Status, loc)
	}

	// we need to nullify the damn redirec-not-allowed error from above
	err = nil
	return
}

// ApplyModsXp changes a SAML message by applying an array of xpath expressions and a value
//     If the value is "" the nodes are unlinked
//     if the value starts with "+ " the the node content is prefixed with the rest of the value
//     Otherwise the node content is replaced with the value
func ApplyModsXp(xp *goxml.Xp, m mods) {
	for _, change := range m {
		if change.Function != nil {
			change.Function(xp, change)
		} else if change.Value == "" {
			for _, element := range xp.Query(nil, change.Path) {
				parent, _ := element.ParentNode()
				parent.RemoveChild(element)
				defer element.Free()
			}
		} else if strings.HasPrefix(change.Value, "+ ") {
			for _, value := range xp.QueryMulti(nil, change.Path) {
				xp.QueryDashP(nil, change.Path, change.Value[2:]+value, nil)
			}
		} else if strings.HasPrefix(change.Value, "- ") {
			for _, value := range xp.QueryMulti(nil, change.Path) {
				xp.QueryDashP(nil, change.Path, value+change.Value[2:], nil)
			}
		} else {
			xp.QueryDashP(nil, change.Path, change.Value, nil)
		}
	}
	//q.Q(string(xp.PP()))
}

// keep it simple for now
func applyModsQuery(u *url.URL, m mods) {
	q := u.Query()
	for _, change := range m {
		q.Set(change.Path, change.Value)
	}
	u.RawQuery = q.Encode()
}

// keep it simple for now
func applyModsCookie(tp *Testparams, m mods) {
	for _, change := range m {
		tp.Cookiejar["wayf.dk"][change.Path] = &http.Cookie{Name: change.Path, Value: change.Value}
	}
}

func (tp *Testparams) newresponse(u *url.URL, m mods) (err error) {
	// get the SAMLRequest
	query := u.Query()
	tp.RelayState = query.Get("RelayState")
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	tp.FinalRequest = goxml.NewXp(gosaml.Inflate(req))

	tp.logxml(tp.FinalRequest)

	switch tp.FinalIdp {
	case "https://login.test-nemlog-in.dk":
		tp.Newresponse = goxml.NewXpFromFile(path+"testdata/nemlogin.encryptedresponse.xml")
		tp.logxml(tp.Newresponse)

		//  case "https://this.is.not.a.valid.idp":
	default:
		if tp.Jwt2SAMLDoRequest {
			//tp.logxml(tp.Newresponse)
			query := u.Query()
			query.Add("sso", tp.FinalRequest.Query1(nil, "@Destination"))
			query.Add("preflight", "1")

			err = tp.Jwt2SAMLDo(query)
			if err != nil {
				return
			}
			query.Del("preflight")

			attrs := map[string]interface{}{}
			for k, v := range testAttributes {
				attrs[k] = v
			}
			attrs["iat"] = time.Now().Unix()
			attrs["saml:AuthnContextClassRef"] = "fake"

			body, err := json.Marshal(attrs)
			if err != nil {
				return err
			}

			payload := base64.RawURLEncoding.EncodeToString(body)
			header := map[string]string{"sha256": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.", "sha512": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9."}[tp.Hashalgorithm]
			signature, err := goxml.Sign([]byte(goxml.Hash(goxml.Algos[tp.Hashalgorithm].Algo, header+payload)), []byte(tp.Privatekey), []byte(tp.Privatekeypw), tp.Hashalgorithm)
			query.Add("jwt", header+payload+"."+base64.RawURLEncoding.EncodeToString(signature))
			err = tp.Jwt2SAMLDo(query)
			if err != nil {
				return err
			}

		} else {
			// create a response
			tp.Newresponse = gosaml.NewResponse(tp.Idpmd, tp.Hubspmd, tp.FinalRequest, nil)
			attrStmt := tp.Attributestmt.Query(nil, "//saml:AttributeStatement")[0]
			tp.Newresponse.Query(nil, "/samlp:Response/saml:Assertion")[0].AddChild(tp.Newresponse.CopyNode(attrStmt, 1))

			ApplyModsXp(tp.Newresponse, m)

			for _, xpath := range tp.ElementsToSign {
				element := tp.Newresponse.Query(nil, xpath)[0]
				before := tp.Newresponse.Query(element, "*[2]")[0]
				err := tp.Newresponse.Sign(element.(types.Element), before.(types.Element), []byte(tp.Privatekey), []byte(tp.Privatekeypw), tp.Certificate, tp.Hashalgorithm)
				if err != nil {
					//              q.Q("Newresponse", err.(goxml.Werror).Stack(2))
					log.Fatal(err)
				}
			}

			//tp.logxml(tp.Newresponse)

			if tp.Encryptresponse {
				assertion := tp.Newresponse.Query(nil, "saml:Assertion[1]")[0]
				cert := tp.Hubspmd.Query1(nil, `//md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
				if cert == "" {
					fmt.Errorf("Could not find encryption cert for: %s", tp.Hubspmd.Query1(nil, "/@entityID"))
				}

				_, publickey, _ := gosaml.PublicKeyInfo(cert)

				err := tp.Newresponse.Encrypt(assertion.(types.Element), publickey)
				if err != nil {
					log.Fatal(err)
				}
				tp.Encryptresponse = false // for now only possible for idp -> hub

				tp.logxml(tp.Newresponse)
			}
		}
	}
	return
}

func ValidateSignature(md, xp *goxml.Xp) (err error) {
	certificates := md.QueryMulti(nil, `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}
	signatures := xp.Query(nil, "(/samlp:Response[ds:Signature] | /samlp:Response/saml:Assertion[ds:Signature] | /t:RequestSecurityTokenResponse/t:RequestedSecurityToken/saml1:Assertion[ds:Signature])")
	destination := xp.Query1(nil, "/samlp:Response/@Destination")

	if len(signatures) == 0 {
		err = fmt.Errorf("%s neither the assertion nor the response was signed", destination)
		return
	}

	for _, signature := range signatures {
		err = gosaml.VerifySign(xp, certificates, signature)
		if err != nil {
			return
		}
	}
	return
}

func TestEduGAINeptid(t *testing.T) {
	stdoutstart()
	eID := testSPs.Query1(nil, "//wayf:wayf[wayf:feds='eduGAIN' and wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/../../md:SPSSODescriptor[md:AttributeConsumingService/md:RequestedAttribute/@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/../@entityID")
	spMd, _ := internalMd.MDQ(eID)
    if spMd == nil {
        log.Fatalln("No SP found for testing eduGAIN eptid format: ")
    }
	res := browse(nil, &overwrites{"Spmd": spMd})
	if res != nil {
		fmt.Print(res.Newresponse.PPE(res.Newresponse.Query(nil, `//saml:Attribute[@Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"]`)[0]))
	}

	expected := `<saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
                NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                FriendlyName="eduPersonTargetedID">
    <saml:AttributeValue>
        <saml:NameID>
          WAYF-DK-7e0ad4ac0f934709fa8182ddd331b44bf641317d
        </saml:NameID>
    </saml:AttributeValue>
</saml:Attribute>
`
	stdoutend(t, expected)
}

func TestSPSLO(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	res := browse(nil, nil)

	spMd, _ := internalMd.MDQ("https://wayfsp2.wayf.dk")
	res = browse(nil, &overwrites{"Spmd": spMd, "Idp": "https://this.is.not.a.valid.external.idp", "Cookiejar": res.Cookiejar})
	browseSLO(res)
	expected := `logout this.is.not.a.valid.external.idp
logout this.is.not.a.valid.idp
logout wayfsp.wayf.dk
logout wayfsp2.wayf.dk
`
	stdoutend(t, expected)
}

func TestSPSLONoSLOSupport(t *testing.T) {
	if dobirk || !*testmdq {
		return
	}
	stdoutstart()
	m := modsset{"cookiemods": mods{mod{"testidp", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, nil)

	entityID := "https://wayfsp2.wayf.dk"
	spMd, _ := internalMd.MDQ(entityID)
	spMd.Rm(nil, "//md:SingleLogoutService")
	idp := "https://this.is.not.a.valid.external.idp"
	res = browse(nil, &overwrites{"Spmd": spMd, "Idp": idp, "Cookiejar": res.Cookiejar})

    // browseSLO does currently not support modsets or overwrites så set the mdqMap entry for the modified sp here
	mdqMap["int"][entityID] = spMd
	mdqMap["int"][gosaml.IDHash(entityID)] = spMd

	browseSLO(res)
	expected := `logout this.is.not.a.valid.external.idp
logout this.is.not.a.valid.idp
logout wayfsp.wayf.dk
["cause:no SingleLogoutService found","entityID:https://wayfsp2.wayf.dk"]
`
	stdoutend(t, expected)
}

func TestSPSLOAsync(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	res := browse(nil, nil)

	spMd, _ := internalMd.MDQ("https://wayfsp2.wayf.dk")
	res = browse(nil, &overwrites{"Spmd": spMd, "Idp": "https://this.is.not.a.valid.external.idp", "Cookiejar": res.Cookiejar})
	res.AsyncSLO = true
	browseSLO(res)
	expected := `logout this.is.not.a.valid.external.idp
logout this.is.not.a.valid.idp
logout wayfsp.wayf.dk
SLO completed
`
	stdoutend(t, expected)
}

// TestAttributeNameFormat tests if the hub delivers the attributes in the correct format - only one (or none) is allowed
// Currently if none is specified we deliver both but lie about the format so we say that it is basic even though it actually is uri
// As PHPH always uses uri we just count the number of RequestedAttributes
func TestAttributeNameFormat(t *testing.T) {
	const (
		mdcounturi   = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		mdcountbasic = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
		mdcount      = "count(//md:RequestedAttribute)"
		ascounturi   = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		ascountbasic = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
	)
	stdoutstart()
	attrnameformats := []string{"uri", "basic"}
	attrnameformatqueries := map[string]string{
		"uri":   "/*/*/*/wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/../../@entityID",
		"basic": "/*/*/*/wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic']/../../@entityID",
	}

	for _, attrname := range attrnameformats {
		eID := testSPs.Query1(nil, attrnameformatqueries[attrname])
		md, _ := internalMd.MDQ(eID)
		if md == nil {
			log.Fatalln("No SP found for testing attributenameformat: ", attrname)
		}
		tp := browse(nil, &overwrites{"Spmd": md, "SAML2jwtDoRequest": false})
		if tp != nil {
			requested := md.QueryNumber(nil, mdcount)
			uricount := tp.Newresponse.QueryNumber(nil, ascounturi)
			basiccount := tp.Newresponse.QueryNumber(nil, ascountbasic)
			fmt.Printf("%t %t\n", uricount == requested, basiccount == requested)
		}
	}
	expected := `true false
false true
`
	stdoutend(t, expected)
}

func TestPostingRequest(t *testing.T) {
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, &overwrites{"Method": "POST"})
	expected := `https://wayfsp.wayf.dk
`
	if res != nil {
		fmt.Println(res.FinalRequest.Query1(nil, "samlp:Scoping/samlp:RequesterID"))
	}
	stdoutend(t, expected)
}

func TestRequesterID(t *testing.T) {
	stdoutstart()
	res := browse(nil, nil)
	expected := `https://wayfsp.wayf.dk
`
	if res != nil {
		fmt.Println(res.FinalRequest.Query1(nil, "samlp:Scoping/samlp:RequesterID"))
	}
	stdoutend(t, expected)
}

func TestJwt2SAML(t *testing.T) {
	stdoutstart()
	res := browse(nil, &overwrites{"Jwt2SAMLDoRequest": true})

	if res != nil {
		fmt.Println(res.Jwt2SAMLResponse, res.FinalRequest.Query1(nil, "samlp:Scoping/samlp:RequesterID"))
	}
	stdoutend(t, jwt2SAMLPreflight)
}

func TestSpecialsubdomain(t *testing.T) {
	stdoutstart()
	m := modsset{
		"presigningresponsemods": mods{
			mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonPrincipalName\"]/saml:AttributeValue", "joe@sub.this.is.not.a.valid.idp", nil},
		}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := `["cause:security domain 'sub.this.is.not.a.valid.idp' does not match any scopes"]
`
    if *testmdq {
        m = modsset{
            "presigningresponsemods": mods{
                mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonPrincipalName\"]/saml:AttributeValue", "joe@sub.ku.dk", nil},
                mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonScopedAffiliation\"]/saml:AttributeValue", "", nil},
                mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonScopedAffiliation\"]/saml:AttributeValue", "student@ku.dk", nil}},
            "mdexternalidpmods": mods{
                mod{"./md:IDPSSODescriptor/md:Extensions/shibmd:Scope", "sub.ku.dk", nil}},
        }
        res = browse(m, nil)
        if res != nil {
            epsa := res.Newresponse.Query1(nil, `//saml:Attribute[@Name="eduPersonScopedAffiliation"]/saml:AttributeValue`)
            fmt.Println(epsa)
        }
        expected += `student@ku.dk
`
    }
	stdoutend(t, expected)
}

func TestKrib(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", "https://this.is.not.a.valid.external.idp", nil}}}
	res := browse(m, &overwrites{"Idp": "https://this.is.not.a.valid.external.idp"})
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

func TestModst(t *testing.T) {
	if dohub {
		return
	}
	stdoutstart()
	md, _ := internalMd.MDQ("https://sso.modst.dk/runtime/")
	res := browse(nil, &overwrites{"Spmd": md})
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}

	stdoutend(t, modstAttributes)
}

func TestAdobe(t *testing.T) {
	if dobirk {
		return
	}
	expected := `gn FirstName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton &lt;SamlRequest id=&#34;abc&#34;&gt;abc&lt;/SamlRequest&gt;
mail Email urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
sn LastName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Cantonsen
`
	stdoutstart()
	m := modsset{"cookiemods": mods{mod{"testidp", "https://this.is.not.a.valid.idp", nil}}}
	md, _ := internalMd.MDQ("https://federatedid-na1.services.adobe.com/federated/saml/metadata/alias/8e858103-4714-4d50-a03d-c52a7e0b6314")
	res := browse(m, &overwrites{"Spmd": md})
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	stdoutend(t, expected)
}

// TestDigestMethods tests that the hub can receive the algos and that the Signature|DigestMethod is what the sp asks for
func TestDigestMethods(t *testing.T) {
	stdoutstart()
	expected := ""
	m := modsset{"cookiemods": mods{mod{"debug", "spSigAlg=sha256", nil}}}
	tp := browse(m, &overwrites{"Hashalgorithm": "sha256"})
	if tp != nil {
		signatureMethod := tp.Newresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := tp.Newresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
http://www.w3.org/2001/04/xmlenc#sha256
`
	}
	m = modsset{"cookiemods": mods{mod{"debug", "spSigAlg=sha512", nil}}}
	tp = browse(m, &overwrites{"Hashalgorithm": "sha512"})
	if tp != nil {
		signatureMethod := tp.Newresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := tp.Newresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `https://www.w3.org/2001/04/xmldsig-more#rsa-sha512
https://www.w3.org/2001/04/xmlenc#sha512
`
	}
	stdoutend(t, expected)
}

// TestConsentDisabled tests that a SP with consent.disabled set actually bypasses the consent form
func TestSigningResponse(t *testing.T) {
	stdoutstart()
	expected := ""
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[wayf:saml20.sign.response='1']/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := internalMd.MDQ(entityID)

		tp := browse(nil, &overwrites{"Spmd": entitymd})
		if tp != nil {
			responseSignatures := len(tp.Newresponse.QueryMulti(nil, "/samlp:Response/ds:Signature"))
			assertionSignatures := len(tp.Newresponse.QueryMulti(nil, "/samlp:Response/saml:Assertion/ds:Signature"))
			fmt.Printf("Response signature = %d Assertion signatures = %d\n", responseSignatures, assertionSignatures)
			expected = `Response signature = 1 Assertion signatures = 0
`
		}
	} else {
		expected += "no entity suited for test found"
	}
	stdoutend(t, expected)
}

// TestConsentDisabled tests that a SP with consent.disabled set actually bypasses the consent form
func TestConsentDisabled(t *testing.T) {
	stdoutstart()
	expected := ""
	// find an entity with consent disabled, but no a birk entity as we know that using ssp does not understand the wayf namespace yet ...
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[wayf:consent.disable='1' or wayf:consent.disable='true']/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := internalMd.MDQ(entityID)

		tp := browse(nil, &overwrites{"Spmd": entitymd})
		if tp != nil {
			fmt.Printf("consent given %t\n", tp.ConsentGiven)
		}
		expected += `consent given false
`
	} else {
		expected += "no entity suited for test found"
	}
	stdoutend(t, expected)
}

// TestConsentDisabled tests that a SP with consent.disabled set actually bypasses the consent form
func TestConsentGiven(t *testing.T) {
	stdoutstart()
	expected := ""
	// find an entity with consent disabled, but no a birk entity as we know that using ssp does not understand the wayf namespace yet ...
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[not(wayf:consent.disable='true' or wayf:consent.disable='1')]/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := internalMd.MDQ(entityID)

		tp := browse(nil, &overwrites{"Spmd": entitymd})
		if tp != nil {
			fmt.Printf("consent given %t\n", tp.ConsentGiven)
		}
		expected += `consent given true
`
	} else {
		expected += "no entity suited for test found"
	}
	stdoutend(t, expected)
}

// TestPersistentNameID tests that the persistent nameID (and eptid) is the same from both the hub and BIRK
func TestPersistentNameID(t *testing.T) {
	expected := ""
	stdoutstart()
	entityID := testSPs.Query1(nil, "/*/*/md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']/../md:AttributeConsumingService/md:RequestedAttribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10' or @Name='eduPersonTargetedID']/../../../@entityID")
	entitymd, _ := internalMd.MDQ(entityID)
	if entitymd == nil {
		return
		//log.Fatalln("no SP found for testing TestPersistentNameID")
	}

	tp := browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		entityID := entitymd.Query1(nil, "@entityID")
		nameidformat := tp.Newresponse.Query1(nil, "//saml:NameID/@Format")
		//nameid := tp.Newresponse.Query1(nil, "//saml:NameID")
		audience := tp.Newresponse.Query1(nil, "//saml:Audience")
		spnamequalifier := tp.Newresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
		//eptid := tp.Newresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10' or @Name='eduPersonTargetedID']/saml:AttributeValue")
		fmt.Printf("%s %s %s\n", nameidformat, audience, spnamequalifier)
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent ` + entityID + ` ` + entityID + "\n"
	}
	stdoutend(t, expected)
}

// TestTransientNameID tests that the transient nameID (and eptid) is the same from both the hub and BIRK
func TestTransientNameID(t *testing.T) {
	stdoutstart()
	var expected string
	eID := testSPs.Query1(nil, "/*/*/*/wayf:wayf/wayf:feds[.='WAYF']/../../../md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:transient']/../../@entityID")
	entitymd, _ := internalMd.MDQ(eID)
	var tp *Testparams
	entityID := ""
	//  m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:Issuer", "+ 1234", nil}}}
	//  m := modsset{"responsemods": mods{mod{"./saml:Assertion/ds:Signature/ds:SignatureValue", "+ 1234", nil}}}
	tp = browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		entityID = entitymd.Query1(nil, "@entityID")
		nameid := tp.Newresponse.Query1(nil, "//saml:NameID")
		nameidformat := tp.Newresponse.Query1(nil, "//saml:NameID/@Format")
		audience := tp.Newresponse.Query1(nil, "//saml:Audience")
		spnamequalifier := tp.Newresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
		fmt.Printf("%s %t %s %s\n", nameidformat, nameid != "", audience, spnamequalifier)
		expected = `urn:oasis:names:tc:SAML:2.0:nameid-format:transient true ` + entityID + ` ` + entityID + "\n"
	}
	stdoutend(t, expected)
}

// TestUnspecifiedNameID tests that the
func TestUnspecifiedNameID(t *testing.T) {
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified", nil}}}
	// BIRK always sends NameIDPolicy/@Format=transient - but respects what the hub sends back - thus we need to fix the request BIRK sends to the hub (WAYFMMISC-940)
	// n := modsset{"birkrequestmods": m["requestmods"]}
	browse(m, nil)
	expected := `nameidpolicy format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified' is not supported
`
	stdoutend(t, expected)
}

func xTestNemLogin(t *testing.T) {
	var expected string
	if *env != "dev" {
		return
	}

	stdoutstart()
	// common res for hub and birk
	expected += `cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
`
	gosaml.TestTime, _ = time.Parse(gosaml.XsDateTime, "2017-10-09T20:48:49.385Z")

	tp := Newtp(&overwrites{"Idp": "https://nemlogin.wayf.dk", "FinalIdp": "https://login.test-nemlog-in.dk"})
	//    cert := ioutil.ReadFile(path+"testdata/2481cb9e1194df81050c7d22b823540b9442112c.X509Certificate")
	//    tp.

	res := browse(nil, tp)

	if true || res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	stdoutend(t, expected)
	gosaml.TestTime = time.Time{}
}

// TestFullAttributeset1 test that the full attributeset is delivered to the default test sp
func TestFullAttributeset(t *testing.T) {
	stdoutstart()
	// common res for hub and birk
	res := browse(nil, nil)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
		// check presence of cert
		fmt.Printf("%t", len(res.Newresponse.Query1(nil, "//ds:KeyInfo/ds:X509Data/ds:X509Certificate")) > 0)
	}
	expected := fullAttributeSet
	expected += `true`
	stdoutend(t, expected)
}

func TestInternalAttributeSet(t *testing.T) {
	if dobirk || !*testmdq {
		return
	}
	stdoutstart()
	m := modsset{"mdspmods": mods{mod{"./md:Extensions/wayf:wayf/wayf:RequestedAttributesEqualsStar", "true", nil}}}
	res := browse(m, nil)
	if res != nil {
		res.Newresponse.Rm(nil, `//saml:Attribute[@Name="nameID"]`) // transient get rid of it - always different
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	stdoutend(t, fullInternalAttributeSet)
}

// TestFullAttributeset1 test that the full attributeset is delivered to the default test sp
func TestFullAttributesetSAMLtojwt(t *testing.T) {
	stdoutstart()
	// common res for hub and birk
	browse(nil, &overwrites{"SAML2jwtDoRequest": true, "SAML2jwtDoResponse": true})
	stdoutend(t, fullAttributeSetJSON)
}

// TestFullAttributeset1 test that the full attributeset is delivered to the default test sp
func TestFullAttributesetWSFed(t *testing.T) {
	stdoutstart()
	// common res for hub and birk
	res := browse(nil, &overwrites{"WSFedDoRequest": true})
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
		// check presence of cert
		fmt.Printf("%t", len(res.Newresponse.Query1(nil, "//ds:KeyInfo/ds:X509Data/ds:X509Certificate")) > 0)
	}
	expected := fullAttributeSet
	expected += `true`
	stdoutend(t, expected)
}

// Test for error caused by missing schacPersonalUniqueID - incident 24112020
func TestMissingSchacPersonalUniqueID(t *testing.T) {
	stdoutstart()
	m := modsset{"attributemods": mods{
	    mod{`//saml:Attribute[@Name="schacPersonalUniqueID"]`, "", nil},
	    mod{`//saml:Attribute[@Name="norEduPersonNIN"]`, "", nil},
	    }}
	res := browse(m, nil)
	if res != nil {
	    fmt.Printf("%t\n", len(res.Newresponse.Query1(nil, `//saml:Attribute[@Name="schacPersonalUniqueID"]`)) == 0)
	    fmt.Printf("%t\n", len(res.Newresponse.Query1(nil, `//saml:Attribute[@Name="norEduPersonNIN"]`)) == 0)
    }
	expected := `true
true
`
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestScopingMd(t *testing.T) {
	if dobirk || !*testmdq {
		return
	}
	stdoutstart()
	m := modsset{"mdspmods": mods{mod{"./md:Extensions/wayf:wayf/wayf:IDPList", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

func TestScopingMdByDomain(t *testing.T) {
	if dobirk || !*testmdq {
		return
	}
	stdoutstart()
	m := modsset{"mdspmods": mods{mod{"./md:Extensions/wayf:wayf/wayf:IDPList", "not.really.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestScopingElement(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestScopingElementByDomain(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", "not.really.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestScopingParam(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"querymods": mods{mod{"idpentityid", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

func TestScopingParamByDomain(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"querymods": mods{mod{"idpentityid", "not.really.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

func TestScopingVVPMSS(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"cookiemods": mods{mod{"vvpmss", "https://this.is.not.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

func TestScopingVVPMSSByDomain(t *testing.T) {
	if dobirk {
		return
	}
	stdoutstart()
	m := modsset{"cookiemods": mods{mod{"vvpmss", "not.really.a.valid.idp", nil}}}
	res := browse(m, nil)
	if res != nil {
		fmt.Printf("%t", res.PassedDisco)
	}
	expected := "false"
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestFullAttributesetSP2(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internalMd.MDQ("https://metadata.wayf.dk/PHPh")
	res := browse(nil, &overwrites{"Spmd": spmd})
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    WAYF-DK-493ee01e49107fed7c4b89622d8087bc5064cc15
mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
`
	stdoutend(t, expected)
}

func TestFullEncryptedAttributeset1(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internalMd.MDQ("https://metadata.wayf.dk/PHPh")
	overwrite := &overwrites{"Encryptresponse": true, "Spmd": spmd}
	res := browse(nil, overwrite)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    WAYF-DK-493ee01e49107fed7c4b89622d8087bc5064cc15
mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
`
	stdoutend(t, expected)
}

func TestAccessForNonIntersectingAdHocFederations(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internalMd.MDQ("https://this.is.not.a.valid.sp")
	overwrite := &overwrites{"Spmd": spmd}
	browse(nil, overwrite)
	expected = `no common federations
`
	stdoutend(t, expected)
}

func TestSignErrorModifiedContent(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:Issuer", "+ 1234", nil}}}
	browse(m, nil)
	expected := `["cause:digest mismatch","err:unable to validate signature"]
`
	stdoutend(t, expected)
}

func TestSamlVulnerability(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonPrincipalName\"]/saml:AttributeValue", "- <!--and.a.fake.domain--->", nil}}}
	browse(m, nil)
	expected := `["cause:digest mismatch","err:unable to validate signature"]
`
	stdoutend(t, expected)
}

func TestSignErrorModifiedSignature(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/ds:Signature/ds:SignatureValue", "+ 1234", nil}}}
	browse(m, nil)
	expected := `["cause:crypto/rsa: verification error","err:unable to validate signature"]
`
	stdoutend(t, expected)
}

// TestNoSignatureError tests if the hub and BIRK reacts assertions that are not signed
func TestNoSignatureError(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//ds:Signature", "", nil}}}
	browse(m, nil)
	expected := `["cause:encryption error"]
`
	stdoutend(t, expected)
}

// TestAuthnInstantPassThru tests that the @AuthnInstant goes unmodified thru the hub
func TestAuthnPassThru(t *testing.T) {
	stdoutstart()
	checks := [][]string{
		{"saml:Assertion/saml:AuthnStatement/@AuthnInstant", "2006-01-02T15:04:05Z"},
		{"saml:Assertion/saml:AuthnStatement/@SessionNotOnOrAfter", "2006-01-02T15:04:05Z"},
		{"saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", "AuthnContextClassRefTestValue"},
	}

	for _, check := range checks {
		m := modsset{"presigningresponsemods": mods{mod{check[0], check[1], nil}}}
		res := browse(m, nil)
		if res != nil {
			fmt.Println(res.Newresponse.Query1(nil, check[0]))
		}
	}
	expected := `2006-01-02T15:04:05Z
2006-01-02T15:04:05Z
AuthnContextClassRefTestValue
`
	stdoutend(t, expected)
}

func TestTiming(t *testing.T) {
	diffs := []string{"300", "-300", "600", "-600"}
	checks := []string{
		"@IssueInstant",
		"saml:Assertion[1]/@IssueInstant",
		"saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter",
		"saml:Assertion[1]/saml:Conditions/@NotBefore",
		"saml:Assertion[1]/saml:Conditions/@NotOnOrAfter",
		//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@AuthnInstant",
		//			"/samlp:Response[1]/saml:Assertion[1]/saml:AuthnStatement/@SessionNotOnOrAfter",
	}

	stdoutstart()
	for _, diff := range diffs {
		for _, check := range checks {
			m := modsset{"presigningresponsemods": mods{mod{check, diff, moddate}}}
			browse(m, nil)
		}
	}
	expected := `timing problem: /samlp:Response[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore
timing problem: /samlp:Response[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/@IssueInstant
timing problem: /samlp:Response[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotBefore
timing problem: /samlp:Response[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/@IssueInstant
timing problem: /samlp:Response[1]/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter
timing problem: /samlp:Response[1]/saml:Assertion[1]/saml:Conditions/@NotOnOrAfter
`
	stdoutend(t, expected, `(?m)^(\S+ \S+ \S+).*`, `$1`)
}

func moddate(xp *goxml.Xp, m mod) {
	xmltime := xp.Query1(nil, m.Path)
	samltime, _ := time.Parse(gosaml.XsDateTime, xmltime)
	diff, _ := strconv.Atoi(m.Value)
	newSamlTime := samltime.Add(time.Duration(diff) * time.Second).UTC()
	xmltime2 := newSamlTime.Format(gosaml.XsDateTime)
	xp.QueryDashP(nil, m.Path, xmltime2, nil)
}

// TestUnknownKeySignatureError tests if the hub and BIRK reacts on signing with an unknown key
func TestUnknownKeySignatureError(t *testing.T) {
	stdoutstart()
	// Just a random private key - not used for anything else
	pk := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsd0urclhDMeNqfmmES6LxVf3mK6CAX3vER1Te8QNLsd1iUEq
inmx+j6TqoyLBuVrQkOSMn7pPQMobjpca81KsWcS00RvZCNAgreTj4jOzfIouSml
6BDjuEPP9GEjQhf5iajenBeKfK8jPVnpxEKsuopE6ueKG5Rpi59mV/iVq7ZMQSGl
504OBKWBkAUgO5dPneB632uJSp2kiy0/YNUp30ItR45TncOqEtkrwBx219pRg2B0
2ot8TwZ8xFD7LG2V/hq8+0Ppp+tzTWDAri5z5ZSrAn0/j8sC56Qcwl2w2sYYhpNx
8T9x1QupnIpR1RyHCqR5mBJWDtO3pLAyPW74EwIDAQABAoIBAG9MixMwusw2a017
7RE/YTNCUqt2N+AbH+hDw6PlEKK/KauT3bz9XgPL+Ld2buEH2tCCXA/BHs6RFVG0
r3S96AmPCFavskylSo8BtRLSdyakbBtCFpFbUERUGuM/jcKkIgCkbXibuos/RPv1
MbUgS9oHAA1GikOr4Uf/nRlbcr0ZsRQnqp9uaK+rMCnypBQFB/YE1eKuTqSXf/Yb
D0+xJ3XDaTalBH2qXfIZX3+hKd7NvL5KHAc5ZVj3LzaBJ6GXV7nIKKbbTbdQdjxe
uEzPj36Zb7ultAorQYIyPHlGiXBh+gpkC3BHxDLwIqG+Iw0wUCnlKTDBO0qq8JcZ
TQAVsmECgYEA2IAosfRHjgWhT40+JTd/DICLoa/VAUeHok1JvjirJwADjDj0oZ6C
Ry5ioxrOpxH1RvHSfCHdKt0/aPviyEJGDRU8d/tFQypeSzDHL/BDQtavw/Na5c9x
epCft6HshpuzPr43IYB/VbiUedm8w78jNIcXEphNgNLaw22uU/3gkfkCgYEA0lB3
t+QJiHXY3J7YHze5jYrK96By9DY8MjkgKLwxaFFGZqpb2egXQK5ohBHuAbZXVGDY
oOH/IOBgdsOYuJv7NKfMY35wzrMygfWXbSNlTZwdrmJPqOSfUwu/hmBuwEHsfrEJ
3a2xiX+OFhfRwebcQwgOrN1FVpobKrXqYjp+3WsCgYB/vu9EQY1PIcdS91ZqA1r1
94tsdiHLRXekrtIKacmjk4CEZr8B9lOMyLPu5cx2DESb/ehi0mB8AFyAB9CCtYg8
BAHQEfWGciN9XmTJxo0JjT/c8WT7IPImjduQMP0tWAXlybsiC34XCHijhXS6U7fk
MKnOkQt6LfBjS/6HFNBDkQKBgBbW0DlzFSnxikxjH5s8RPU/Bk2f6fvlS+I0W+6w
iTkH4npRs8nVL3lBt23oOI2NDKzIG55VDIy4cSFUmmgp4DzWoBaJ65w2z5xXXEto
1Z54/qwqVvZDZZ3yH6lrHXvZbOJRPX4KV8ZTyM1TZt8EwBSzckyJdvcxoxOfT8W9
DnvjAoGAIu1AHwMhBdGmwffsII1VAb7gyYnjFbPfaSrwaxIMJ61Djayg4XhGFJ5+
NDVIEaV6/PITFgNcYIzBZxgCEqZ6jJ5jiidlnUbGPYaMhPN/mmHCP/2dvYW6ZSGC
mYqIGJZzLM/wk1u/CG52i+zDOiYbeiYNZc7qhIFU9ueinr88YZo=
-----END RSA PRIVATE KEY-----
`

	// need to do resign before sending to birk - not able to do that pt
	//  _ = DoRunTestBirk(nil)
	browse(nil, &overwrites{"Privatekey": pk, "Privatekeypw": "-"})
	expected := `["cause:crypto/rsa: verification error","err:unable to validate signature"]
`
	stdoutend(t, expected)
}

// TestRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestRequestSchemaError(t *testing.T) {
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse", nil}}}
	browse(m, nil)
	expected := `["cause:schema validation failed"]
`
	stdoutend(t, expected)
}

// TestResponseSchemaError tests that the HUB and BIRK reacts on schema errors in responses
func TestResponseSchemaError(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./@IssueInstant", "isfalse", nil}}}
	browse(m, nil)
	expected := `["cause:schema validation failed"]
`
	stdoutend(t, expected)
}

// TestNoEPPNError tests that the hub does not accept assertions with no eppn
func TestNoEPPNError(t *testing.T) {
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil}}}
	browse(m, nil)
	expected := `["cause:isRequired: eduPersonPrincipalName"]
`
	stdoutend(t, expected)
}

// TestEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func TestEPPNDomainError(t *testing.T) {
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe@example.com", nil}}}
	browse(m, nil)
	expected := `["cause:security domain 'example.com' does not match any scopes"]
`
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func TestNoLocalpartInEPPNError(t *testing.T) {
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue[1]`, "@this.is.not.a.valid.idp", nil}}}
	browse(m, nil)
	expected := `["cause:not a scoped value: @this.is.not.a.valid.idp"]
`
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func TestNoDomainInEPPNError(t *testing.T) {
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue[1]`, "joe", nil}}}
	browse(m, nil)
	expected := `["cause:not a scoped value: joe"]
`
	stdoutend(t, expected)
}

// TestUnknownSPError test how the birk and the hub reacts on requests from an unknown sP
func TestUnknownSPError(t *testing.T) {
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./saml:Issuer", "https://www.example.com/unknownentity", nil}}}
	browse(m, nil)
	expected := `["cause:Metadata not found","err:Metadata not found","key:https://www.example.com/unknownentity","table:sp"]
`
	stdoutend(t, expected)
}

// TestUnknownIDPError tests how BIRK reacts on requests to an unknown IdP
// Use the line below for new birkservers
// Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
func TestUnknownIDPError(t *testing.T) {
	stdoutstart()
	var m modsset
	var expected string
	switch *do {
	case "hub":
		m = modsset{"requestmods": mods{mod{"./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", "https://wayf.wayf.dk/unknownentity", nil}}}
		expected = `["cause:Metadata not found","err:Metadata not found","key:https://wayf.wayf.dk/unknownentity","table:idp"]
`
	case "birk":
		m = modsset{"requestmods": mods{mod{"./@Destination", "https://birk.wayf.dk/birk.php/wayf.wayf.dk/unknownentity", nil}}}
		expected = `["cause:Metadata not found","err:Metadata not found","key:https://birk.wayf.dk/birk.php/wayf.wayf.dk/unknownentity","table:idp"]
`
	}
	browse(m, nil)
	stdoutend(t, expected)
}

func TestXSW1(t *testing.T) {
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"", "", ApplyXSW1}}}
	browse(m, nil)
	expected := `["cause:schema validation failed"]
`
	stdoutend(t, expected)
}

// from https://github.com/SAMLRaider/SAMLRaider/blob/master/src/main/java/helpers/XSWHelpers.java
func ApplyXSW1(xp *goxml.Xp, m mod) {
	//log.Println(xp.PP())
	assertion := xp.Query(nil, "/samlp:Response[1]/saml:Assertion[1]")[0]
	clonedAssertion := xp.CopyNode(assertion, 1)
	signature := xp.Query(clonedAssertion, "./ds:Signature")[0]
	//log.Println(goxml.NewXpFromNode(signature).PP())
	parent, _ := signature.(types.Element).ParentNode()
	parent.RemoveChild(signature)
	defer signature.Free()
	//log.Println(goxml.NewXpFromNode(clonedAssertion).PP())
	newSignature := xp.Query(assertion, "ds:Signature[1]")[0]
	newSignature.AddChild(clonedAssertion)
	assertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	//log.Println(xp.PP())
}

func xTestSpeed(t *testing.T) {
	if dobirk {
		return
	}

	sps := testSPs.QueryMulti(nil, "//md:EntityDescriptor/@entityID")
    //numofsps := len(sps)
    PP(sps)

	const gorutines =  40
	const iterations = 1000
	for i := 0; i < gorutines; i++ {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < iterations; j++ {
				starttime := time.Now()
				sp := sps[j % 200]
				spmd, _ := internalMd.MDQ(sp)
	            overwrite := &overwrites{"Encryptresponse": rand.Intn(10) < 10, "Spmd": spmd}
				browse(nil, overwrite)
				log.Println(i, j, sp, time.Since(starttime).Seconds())
				//runtime.GC()
				//time.Sleep(200 * time.Millisecond)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		s, _ := json.MarshalIndent(e, "", "    ")
		fmt.Println(string(s))
	}
	return
}
