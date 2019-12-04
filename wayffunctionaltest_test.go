package wayffunctionaltest

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	toml "github.com/pelletier/go-toml"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lMDQ"
	"github.com/wayf-dk/wayfhybrid"
	"github.com/y0ssar1an/q"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	//	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf
	_ = q.Q
)

type (
	Testparams struct {
		Idp, BirkIdp, FinalIdp                             string
		Spmd, Idpmd, Hubidpmd, Hubspmd, Birkmd, Firstidpmd *goxml.Xp
		Cookiejar                                          map[string]map[string]*http.Cookie
		IdpentityID                                        string
		DSIdpentityID                                      string
		//		Resolv                                             map[string]string
		Initialrequest                 *goxml.Xp
		Newresponse                    *goxml.Xp
		Resp                           *http.Response
		Responsebody                   []byte
		Err                            error
		Trace, Logxml, Encryptresponse bool
		Privatekey                     string
		Privatekeypw                   string
		Certificate                    string
		Hashalgorithm                  string
		Attributestmt                  *goxml.Xp
		Hub                            bool
		Birk                           bool
		Env                            string
		ConsentGiven                   bool
		ElementsToSign                 []string
	}

	overwrites map[string]interface{}

	mod struct {
		path, value string
		function    func(*goxml.Xp)
	}

	mods []mod

	modsset map[string]mods
	M       map[string]interface{} // just an alias
)

const lMDQ_METADATA_SCHEMA_PATH = "src/github.com/wayf-dk/goxml/schemas/ws-federation.xsd"

var (
	mdsources = map[string]map[string]string{
		"prodz": {
			"hub":         "../hybrid-metadata-test.mddb",
			"internal":    "../hybrid-metadata.mddb",
			"externalIdP": "../hybrid-metadata-test.mddb",
			"externalSP":  "../hybrid-metadata.mddb",
		},
		"prod": {
			"hub":         "../hybrid-metadata.mddb",
			"internal":    "../hybrid-metadata.mddb",
			"externalIdP": "../hybrid-metadata.mddb",
			"externalSP":  "../hybrid-metadata.mddb",
		},
		"dev": {
			"hub":         "../hybrid-metadata-test.mddb",
			"internal":    "../hybrid-metadata-test.mddb",
			"externalIdP": "../hybrid-metadata-test.mddb",
			"externalSP":  "../hybrid-metadata-test.mddb",
		},
	}

	wayf_hub_public, internal, externalIdP, externalSP *lMDQ.MDQ
	Md                                                 wayfhybrid.MdSets

	testAttributes = map[string][]string{
		"eduPersonPrincipalName": {"joe@this.is.not.a.valid.idp"},
		"mail":                       {"joe@example.com"},
		"gn":                         {`Anton Banton <SamlRequest id="abc">abc</SamlRequest>`},
		"sn":                         {"Cantonsen"},
		"norEduPersonLIN":            {"123456789"},
		"eduPersonScopedAffiliation": {"student@this.is.not.a.valid.idp", "member@this.is.not.a.valid.idp"},
		"preferredLanguage":          {"da"},
		"eduPersonEntitlement":       {"https://example.com/course101"},
		"eduPersonAssurance":         {"2"},
		"organizationName":           {"Orphanage - home for the homeless"},
		"cn":                         {"Anton Banton Cantonsen"},
		"eduPersonPrimaryAffiliation": {"student"},
		"eduPersonAffiliation":        {"alum"},
		"schacHomeOrganizationType":   {"abc"},
		"schacPersonalUniqueID":       {"urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234"},
		"schacCountryOfCitizenship":   {"dk"},
		"displayName":                 {"Anton Banton Cantonsen"},
	}

	do           = flag.String("do", "hub", "Which tests to run")
	hub          = flag.String("hub", "wayf.wayf.dk", "the hostname for the hub server to be tested")
	hubbe        = flag.String("hubbe", "", "the hub backend server")
	birk         = flag.String("birk", "birk.wayf.dk", "the hostname for the BIRK server to be tested")
	birkbe       = flag.String("birkbe", "", "the birk backend server")
	ds           = flag.String("ds", "ds.wayf.dk", "the discovery server")
	trace        = flag.Bool("xtrace", false, "trace the request/response flow")
	logxml       = flag.Bool("logxml", false, "dump requests/responses in xml")
	env          = flag.String("env", "prod", "which environment to test dev, hybrid, prod - if not dev")
	refreshmd    = flag.Bool("refreshmd", true, "update local metadatcache before testing")
	testcertpath = flag.String("testcertpath", "/etc/ssl/wayf/certs/wildcard.test.lan.pem", "path to the testing cert")

	testSPs *goxml.Xp

	dohub, dobirk bool

	old, r, w      *os.File
	outC           = make(chan string)
	templatevalues = map[string]map[string]string{
		"prod": {
			"eptid":   "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
		},
		"prodz": {
			"eptid":   "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
			"pnameid": "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
		},
		"dev": {
			"eptid":   "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
			"pnameid": "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
		},
		"hybrid": {
			"eptid":   "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
			"pnameid": "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
		},
	}
	resolv map[string]string
	wg     sync.WaitGroup
	tr     *http.Transport
	client *http.Client
)

func TestMain(m *testing.M) {
	flag.Parse()
	dohub = *do == "hub"
	dobirk = *do == "birk"
	log.Printf("do: %q hub: %q backend: %q birk: %q backend: %q\n", *do, *hub, *hubbe, *birk, *birkbe)

	Md.Hub = &lMDQ.MDQ{Path: "file:" + mdsources[*env]["hub"] + "?mode=ro", Table: "HYBRID_HUB"}
	Md.Internal = &lMDQ.MDQ{Path: "file:" + mdsources[*env]["internal"] + "?mode=ro", Table: "HYBRID_INTERNAL"}
	Md.ExternalIdP = &lMDQ.MDQ{Path: "file:" + mdsources[*env]["externalIdP"] + "?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	Md.ExternalSP = &lMDQ.MDQ{Path: "file:" + mdsources[*env]["externalSP"] + "?mode=ro", Table: "HYBRID_EXTERNAL_SP"}
	for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.(*lMDQ.MDQ).Open()
		if err != nil {
			panic(err)
		}
	}

	tomlConfig, err := toml.LoadFile(wayfhybrid.X.Path + "hybrid-config/hybrid-config.toml")

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s\n", err))
	}
	err = tomlConfig.Unmarshal(wayfhybrid.X)
	if err != nil {
		panic(fmt.Errorf("Fatal error %s\n", err))
	}

	for _, ad := range wayfhybrid.X.AttributeDescriptions {
		k := wayfhybrid.AttributeKey{ad.Name, wayfhybrid.X.AttributenameFormats[ad.Nameformat].Ns}
		wayfhybrid.AttributeDescriptions[k] = ad
		wayfhybrid.AttributeDescriptionsList[ad.Nameformat] = append(wayfhybrid.AttributeDescriptionsList[ad.Nameformat], ad)
	}

	//gosaml.Config.CertPath = "testdata/"
	//wayfhybrid.Md = Md
	//go wayfhybrid.Main()

	// need non-birk, non-request.validate and non-IDPList SPs for testing ....
	var numberOfTestSPs int
	testSPs, numberOfTestSPs, _ = Md.Internal.MDQFilter("/md:EntityDescriptor/md:Extensions/wayf:wayf[wayf:federation='WAYF' and not(wayf:IDPList)]/../../md:SPSSODescriptor/..")
	if numberOfTestSPs == 0 {
		log.Fatal("No testSP candidates")
	}

	resolv = map[string]string{"wayf.wayf.dk:443": *hub + ":443", "birk.wayf.dk:443": *birk + ":443", "krib.wayf.dk:443": *hub + ":443", "ds.wayf.dk:443": *ds + ":443"}

	tr = &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		Dial:               func(network, addr string) (net.Conn, error) { return net.Dial(network, resolv[addr]) },
		DisableCompression: true,
	}

	client = &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("redirect-not-allowed") },
	}

	os.Exit(m.Run())
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

func stdoutend(t *testing.T, expected string) {
	// back to normal state
	var b bytes.Buffer
	w.Close()
	os.Stdout = old // restoring the real stdout
	got := <-outC

	tmpl := template.Must(template.New("expected").Parse(expected))
	_ = tmpl.Execute(&b, templatevalues[*env])
	expected = b.String()
	if expected == "" {
		//		t.Errorf("unexpected empty expected string\n")
	}
	if expected != got {
		t.Errorf("\nexpected:\n%s\ngot:\n%s\n", expected, got)
	}
	//fmt.Printf("\nexpected:\n%s\ngot:\n%s\n", expected, got)
}

func Newtp(overwrite *overwrites) (tp *Testparams) {
	tp = new(Testparams)
	tp.Privatekeypw = os.Getenv("PW")
	if tp.Privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp.Env = *env
	tp.Hub = dohub
	tp.Birk = dobirk
	tp.Trace = *trace
	tp.Logxml = *logxml
	tp.Hashalgorithm = "sha256"
	tp.ElementsToSign = []string{"saml:Assertion[1]"}

	tp.Idp = "https://this.is.not.a.valid.idp"
	tp.FinalIdp = tp.Idp
	tp.Spmd, _ = Md.Internal.MDQ("https://wayfsp.wayf.dk")

	if overwrite != nil { // overwrite default values with test specific values while it still matters
		for k, v := range *overwrite {
			reflect.ValueOf(tp).Elem().FieldByName(k).Set(reflect.ValueOf(v))
		}
	}

	// don't use urn:... entityID'ed IdPs for now
	tp.BirkIdp = regexp.MustCompile("^(https?://)(.*)$").ReplaceAllString(tp.Idp, "${1}birk.wayf.dk/birk.php/$2")
	tp.Hubidpmd, _ = Md.Hub.MDQ("https://wayf.wayf.dk")
	tp.Hubspmd = tp.Hubidpmd
	tp.Idpmd, _ = Md.Internal.MDQ(tp.Idp)
	tp.Birkmd, _ = Md.ExternalIdP.MDQ(tp.BirkIdp)

	tp.DSIdpentityID = tp.Idp
	switch *do {
	case "hub":
		tp.Firstidpmd = tp.Hubidpmd
		tp.DSIdpentityID = tp.BirkIdp
	case "birk":
		tp.Firstidpmd = tp.Birkmd
	}

	tp.Cookiejar = make(map[string]map[string]*http.Cookie)
	tp.Cookiejar["wayf.dk"] = make(map[string]*http.Cookie)
	tp.Cookiejar["wayf.dk"]["wayfid"] = &http.Cookie{Name: "wayfid", Value: *hubbe}
	//tp.Cookiejar["wayf.dk"] = make(map[string]*http.Cookie)
	tp.Cookiejar["wayf.dk"]["birkid"] = &http.Cookie{Name: "birkid", Value: *birkbe}

	tp.Attributestmt = newAttributeStatement(testAttributes)

	cert := tp.Idpmd.Query1(nil, `//md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
	if cert == "" {
		fmt.Errorf("Could not find signing cert for: %s", tp.Idpmd.Query1(nil, "/@entityID"))
	}
	tp.Certificate = cert
	keyname, _, err := gosaml.PublicKeyInfo(cert)
	if err != nil {
		log.Fatal(err)
	}

	pk, err := ioutil.ReadFile("signing/" + keyname + ".key")
	if err != nil {
		log.Fatal(err)
	}
	tp.Privatekey = string(pk)
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
	ats.QueryDashP(nil, "./saml:Subject/saml:NameID", gosaml.Id(), nil)
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

// Does what the browser does follow redirects and POSTs and displays errors
func browse(m modsset, overwrite interface{}) (tp *Testparams) {
	var htmlresponse *goxml.Xp
	switch t := overwrite.(type) {
	case *overwrites:
		tp = Newtp(t)
	case *Testparams:
		tp = t
	case nil:
		tp = Newtp(nil)
	}
	stage := map[string]string{"hub": "wayf.wayf.dk", "birk": "wayf.wayf.dk"}[*do]

	ApplyMods(tp.Attributestmt, m["attributemods"])
	tp.Initialrequest, _ = gosaml.NewAuthnRequest(nil, tp.Spmd, tp.Firstidpmd, []string{tp.IdpentityID}, "")
	ApplyMods(tp.Initialrequest, m["requestmods"])
	u, _ := gosaml.SAMLRequest2Url(tp.Initialrequest, "", "", "", "")

	// when to stop
	finalDestination, _ := url.Parse(tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL"))
	finalIdp, _ := url.Parse(tp.FinalIdp)
	redirects := 7
	method := "GET"
	body := ""
	for {
		redirects--
		if redirects == 0 { // if we go wild ...
			return
		}
		if method == "POST" {
			tp.logxml(tp.Newresponse)
			acs := tp.Newresponse.Query1(nil, "@Destination")
			issuer, _ := url.Parse(tp.Newresponse.Query1(nil, "./saml:Issuer"))
			if (tp.Birk || tp.Hub) && map[string]bool{"birk.wayf.dk": true, "wayf.wayf.dk": true}[issuer.Host] {
				// in the new hybrid consent is made in js - and the flag for bypassing it is in js - sad!
				tp.ConsentGiven = strings.Contains(htmlresponse.PP(), `,"BypassConfirmation":false`)
			}
			u, _ = url.Parse(acs)
			//q.Q(u, finalDestination)
			if u.Host == finalDestination.Host {
				tp.logxml(tp.Newresponse)
				err := ValidateSignature(tp.Firstidpmd, tp.Newresponse)
				if err != nil {
					fmt.Printf("signature errors: %s\n", err)
				}
				break
			}
			if u.Host == stage { // only change the response to the place we are actually testing (wayf|birk|krib).wayf.dk
				ApplyMods(tp.Newresponse, m["responsemods"])
			}

			data := url.Values{}
			data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tp.Newresponse.Doc.Dump(false))))
			body = data.Encode()
			//log.Println("SAMLResponse", tp.Newresponse.PP())
		} else {
			tp.logxml(u)
		}

		//q.Q("u", method, redirects, u)
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, method, body, tp.Cookiejar)
		if tp.Err != nil {
			switch tp.Err.(type) {
			case *url.Error:
				log.Panic()
			default:
				q.Q(tp.Err)
				return nil
			}
		}
		htmlresponse = goxml.NewHtmlXp(tp.Responsebody)
		// delete stuff that just  takes too much space when debugging
		tp.Resp.TLS = nil
		tp.Resp.Body = nil
		//q.Q("resp", tp, tp.Err, tp.Resp, string(tp.Responsebody))
		if u, _ = tp.Resp.Location(); u != nil { // we don't care about the StatusCode - Location means redirect
			if tp.Err == nil {
				query := u.Query()
				// we got to a discoveryservice - choose our testidp
				if len(query["return"]) > 0 && len(query["returnIDParam"]) > 0 {
					u, _ = url.Parse(query["return"][0])
					q := u.Query()
					q.Set(query["returnIDParam"][0], tp.DSIdpentityID)
					u.RawQuery = q.Encode()
				} else if strings.Contains(u.Path, "getconsent.php") { // hub consent
					u.RawQuery = u.RawQuery + "&yes=1"
					tp.ConsentGiven = true
				}
			}
			//q.Q(u.Host, finalIdp.Host)
			if u.Host != finalIdp.Host {
				method = "GET"
				body = ""
			} else { // we have reached our IdP
				tp.newresponse(u)
				method = "POST"
			}
			continue
		}
		if tp.Resp.StatusCode == 500 {
			error := ""
			if tp.Resp.Header.Get("content-type") == "text/html" { // hub errors
				error = htmlresponse.Query1(nil, `//a[@id="errormsg"]/text()`)
			} else { // birk & krib errors
				error = string(tp.Responsebody)
				error = regexp.MustCompile("^\\d* ").ReplaceAllString(error, "")
			}
			fmt.Println(strings.Trim(error, "\n "))
			break
		} else {
			tp.Newresponse, _ = gosaml.Html2SAMLResponse(tp.Responsebody)
			if tp.Newresponse.Query1(nil, ".") == "" { // from old hub - disjoint federations
				fmt.Println("unknown error")
				break
			}
			method = "POST"
		}
	}
	if tp.Trace {
		log.Println()
	}
	return
}

func (tp *Testparams) newresponse(u *url.URL) {
	// get the SAMLRequest
	query := u.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	authnrequest := goxml.NewXp(gosaml.Inflate(req))

	tp.logxml(authnrequest)

	switch tp.FinalIdp {
	case "https://login.test-nemlog-in.dk":
		tp.Newresponse = goxml.NewXpFromFile("testdata/nemlogin.encryptedresponse.xml")
		tp.logxml(tp.Newresponse)

	case "https://this.is.not.a.valid.idp":
		// create a response
		tp.Newresponse = gosaml.NewResponse(tp.Idpmd, tp.Hubspmd, authnrequest, tp.Attributestmt)
		wayfhybrid.CopyAttributes(tp.Attributestmt, tp.Newresponse, tp.Hubspmd)

		for _, xpath := range tp.ElementsToSign {
			element := tp.Newresponse.Query(nil, xpath)[0]
			before := tp.Newresponse.Query(element, "*[2]")[0]
			err := tp.Newresponse.Sign(element.(types.Element), before.(types.Element), []byte(tp.Privatekey), []byte(tp.Privatekeypw), tp.Certificate, tp.Hashalgorithm)
			if err != nil {
				//				q.Q("Newresponse", err.(goxml.Werror).Stack(2))
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

			if tp.Env == "xdev" {
				cert, err := ioutil.ReadFile(*testcertpath)
				pk, err := x509.ParseCertificate(cert)
				if err != nil {
					return
				}
				publickey = pk.PublicKey.(*rsa.PublicKey)
			}

			ea := goxml.NewXpFromString(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
			err := tp.Newresponse.Encrypt(assertion.(types.Element), publickey, ea)
			if err != nil {
				log.Fatal(err)
			}
			tp.Encryptresponse = false // for now only possible for idp -> hub

			tp.logxml(tp.Newresponse)
		}
	}
}

// SendRequest sends a http request - GET or POST using the supplied url, server, method and cookies
// It updates the cookies and returns a http.Response and a posssible response body and error
// The server parameter contains the dns name of the actual server, which should respond to the host part of the url
func (tp *Testparams) sendRequest(url *url.URL, method, body string, cookies map[string]map[string]*http.Cookie) (resp *http.Response, responsebody []byte, err error) {
	var payload io.Reader
	if method == "POST" {
		payload = strings.NewReader(body)
	}

	host := url.Host
	cookiedomain := "wayf.dk"
	req, err := http.NewRequest(method, url.String(), payload)

	for _, cookie := range cookies[cookiedomain] {
		req.AddCookie(cookie)
	}

	if method == "POST" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Content-Length", strconv.Itoa(len(body)))
	}

	req.Header.Add("Host", host)
	resp, err = client.Do(req)
	if err != nil && !strings.HasSuffix(err.Error(), "redirect-not-allowed") {
		// we need to do the redirect ourselves so a self inflicted redirect "error" is not an error
		log.Println(err)
		debug.PrintStack()
		return nil, nil, errors.New("emit macho dwarf: elf header corrupted")
		//log.Fatalln("client.do", err)
	}

	location, _ := resp.Location()
	loc := ""
	if location != nil {
		loc = location.Host + location.Path
	}

	setcookies := resp.Cookies()
	for _, cookie := range setcookies {
		if cookies[cookiedomain] == nil {
			cookies[cookiedomain] = make(map[string]*http.Cookie)
		}
		cookies[cookiedomain][cookie.Name] = cookie
	}

	// We can't get to the body if we got a redirect pseudo error above
	if err == nil {
		responsebody, err = ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
	}

	// We didn't get a Location: header - we are POST'ing a SAMLResponse
	if loc == "" {
		response := goxml.NewHtmlXp(responsebody)
		samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
		if samlbase64 != "" {
			samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
			samlresponse := goxml.NewXp(samlxml)
			u, _ := url.Parse(samlresponse.Query1(nil, "@Destination"))
			loc = u.Host + u.Path
		}
	}

	if tp.Trace {
		log.Printf("%-4s %-70s %s %-15s %s\n", req.Method, host+req.URL.Path, resp.Proto, resp.Status, loc)
	}

	// we need to nullify the damn redirec-not-allowed error from above
	err = nil
	return
}

// ApplyMods changes a SAML message by applying an array of xpath expressions and a value
//     If the value is "" the nodes are unlinked
//     if the value starts with "+ " the the node content is prefixed with the rest of the value
//     Otherwise the node content is replaced with the value
func ApplyMods(xp *goxml.Xp, m mods) {
	for _, change := range m {
		if change.function != nil {
			change.function(xp)
		} else if change.value == "" {
			//log.Printf("changeval: '%s'\n", change.value)
			for _, element := range xp.Query(nil, change.path) {
				//log.Printf("unlink: %s\n", change.path)
				parent, _ := element.ParentNode()
				parent.RemoveChild(element)
				defer element.Free()
			}
		} else if strings.HasPrefix(change.value, "+ ") {
			for _, value := range xp.QueryMulti(nil, change.path) {
				xp.QueryDashP(nil, change.path, change.value[2:]+value, nil)
			}
		} else if strings.HasPrefix(change.value, "- ") {
			for _, value := range xp.QueryMulti(nil, change.path) {
				xp.QueryDashP(nil, change.path, value+change.value[2:], nil)
			}
		} else {
			xp.QueryDashP(nil, change.path, change.value, nil)
		}
	}
	//q.Q(string(xp.PP()))
}

func ValidateSignature(md, xp *goxml.Xp) (err error) {
	certificates := md.QueryMulti(nil, `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
	if len(certificates) == 0 {
		err = errors.New("no certificates found in metadata")
		return
	}
	signatures := xp.Query(nil, "(/samlp:Response[ds:Signature] | /samlp:Response/saml:Assertion[ds:Signature])")
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
		md, _ := Md.Internal.MDQ(eID)
		if md == nil {
			log.Fatalln("No SP found for testing attributenameformat: ", attrname)
		}
		tp := browse(nil, &overwrites{"Spmd": md})
		if tp != nil {
			//samlresponse := Html2SAMLResponse(tp)
			requested := md.QueryNumber(nil, mdcount)
			uricount := tp.Newresponse.QueryNumber(nil, ascounturi)
			basiccount := tp.Newresponse.QueryNumber(nil, ascountbasic)
			fmt.Printf("%t %t %t\n", basiccount == requested*2, uricount == requested, basiccount == requested)
			//fmt.Printf("requested %d uri %d basic %d\n", requested, uricount, basiccount)
		}
	}
	expected := ""
	if dohub || dobirk {
		expected += `false true false
false false true
`
	}
	stdoutend(t, expected)
}

// TestMultipleSPs tests just test a lot of SPs - if any fails signature validation it fails
func xTestMultipleSPs(t *testing.T) {
	stdoutstart()

	spquery := "/*/*/@entityID"

	eIDs := testSPs.QueryMulti(nil, spquery)

	for _, eID := range eIDs {
		log.Println("eID", eID)
		md, _ := Md.Internal.MDQ(eID)
		if md == nil {
			log.Fatalln("No SP found for testing multiple SPs: ", eID)
		}
		if md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:feds[.='eduGAIN']") == "eduGAIN" {
			continue
		}
		if md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:feds[.='WAYF']") == "" {
			continue
		}
		log.Println("eID", eID)
		browse(nil, &overwrites{"Spmd": md})
	}

	expected := ""
	stdoutend(t, expected)
}

// TestDigestMethodSha1 tests that the Signature|DigestMethod is what the sp asks for
func xTestDigestMethodSendingSha1(t *testing.T) {
	stdoutstart()
	expected := ""
	entitymd, _ := Md.Internal.MDQ("https://metadata.wayf.dk/PHPh")

	tp := browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		signatureMethod := samlresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := samlresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `http://www.w3.org/2000/09/xmldsig#rsa-sha1
http://www.w3.org/2000/09/xmldsig#sha1
`
	}
	stdoutend(t, expected)
}

// TestDigestMethodSha256_1 tests that the Signature|DigestMethod is what the sp asks for
func TestDigestMethodSendingSha256(t *testing.T) {
	stdoutstart()
	expected := ""
	entitymd, _ := Md.Internal.MDQ("https://wayfsp2.wayf.dk")
	//entitymd, _ := Md.Internal.MDQ("https://ucsyd.papirfly.com/AuthServices")

	tp := browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		signatureMethod := samlresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := samlresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
http://www.w3.org/2001/04/xmlenc#sha256
`
	}
	stdoutend(t, expected)
}

// TestDigestMethodSha1 tests that the Signature|DigestMethod is what the sp asks for
func xTestDigestMethodReceivingSha1(t *testing.T) {
	stdoutstart()
	expected := ""
	entitymd, _ := Md.Internal.MDQ("https://metadata.wayf.dk/PHPh")

	tp := browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		signatureMethod := samlresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := samlresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `http://www.w3.org/2000/09/xmldsig#rsa-sha1
http://www.w3.org/2000/09/xmldsig#sha1
`
	}
	stdoutend(t, expected)
}

// TestDigestMethodSha256_1 tests that the Signature|DigestMethod is what the sp asks for
func TestDigestMethodReceivingSha256(t *testing.T) {
	stdoutstart()
	expected := ""
	entitymd, _ := Md.Internal.MDQ("https://wayfsp2.wayf.dk")
	//entitymd, _ := Md.Internal.MDQ("https://ucsyd.papirfly.com/AuthServices")

	tp := browse(nil, &overwrites{"Spmd": entitymd, "Hashalgorithm": "sha256"})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		signatureMethod := samlresponse.Query1(nil, "//ds:SignatureMethod/@Algorithm")
		digestMethod := samlresponse.Query1(nil, "//ds:DigestMethod/@Algorithm")
		fmt.Printf("%s\n%s\n", signatureMethod, digestMethod)
		expected += `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
http://www.w3.org/2001/04/xmlenc#sha256
`
	}
	stdoutend(t, expected)
}

// TestConsentDisabled tests that a SP with consent.disabled set actually bypasses the consent form
func TestSigningResponse(t *testing.T) {
	stdoutstart()
	expected := ""
	// find an entity with consent disabled, but no a birk entity as we know that using ssp does not understand the wayf namespace yet ...
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[wayf:saml20.sign.response='1']/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := Md.Internal.MDQ(entityID)

		tp := browse(nil, &overwrites{"Spmd": entitymd})
		if tp != nil {
			samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
			responseSignatures := len(samlresponse.QueryMulti(nil, "/samlp:Response/ds:Signature"))
			assertionSignatures := len(samlresponse.QueryMulti(nil, "/samlp:Response/saml:Assertion/ds:Signature"))
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
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[wayf:consent.disable='1']/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := Md.Internal.MDQ(entityID)

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
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[not(wayf:consent.disable='1')]/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := Md.Internal.MDQ(entityID)

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
func xTestPersistentNameID(t *testing.T) {
	expected := ""
	stdoutstart()
	defer stdoutend(t, expected)
	entityID := testSPs.Query1(nil, "/*/*/md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']/../md:AttributeConsumingService/md:RequestedAttribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10' or @Name='eduPersonTargetedID']/../../../@entityID")
	log.Println("ent", entityID)
	entitymd, _ := Md.Internal.MDQ(entityID)
	if entitymd == nil {
		return
		//log.Fatalln("no SP found for testing TestPersistentNameID")
	}

	tp := browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		entityID := entitymd.Query1(nil, "@entityID")
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		audience := samlresponse.Query1(nil, "//saml:Audience")
		spnamequalifier := samlresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
		eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10' or @Name='eduPersonTargetedID']/saml:AttributeValue")
		fmt.Printf("%s %s %s %s %s\n", nameidformat, nameid, eptid, audience, spnamequalifier)
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent {{.pnameid}} {{.eptid}} ` + entityID + ` ` + entityID + "\n"
	}
}

// TestTransientNameID tests that the transient nameID (and eptid) is the same from both the hub and BIRK
func TestTransientNameID(t *testing.T) {
	stdoutstart()
	var expected string
	eID := testSPs.Query1(nil, "/*/*/*/wayf:wayf/wayf:feds[.='WAYF']/../../../md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:transient']/../../@entityID")
	entitymd, _ := Md.Internal.MDQ(eID)
	var tp *Testparams
	entityID := ""
	//	m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:Issuer", "+ 1234", nil}}}
	//	m := modsset{"responsemods": mods{mod{"./saml:Assertion/ds:Signature/ds:SignatureValue", "+ 1234", nil}}}
	tp = browse(nil, &overwrites{"Spmd": entitymd})
	if tp != nil {
		samlresponse, _ := gosaml.Html2SAMLResponse(tp.Responsebody)
		entityID = entitymd.Query1(nil, "@entityID")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		audience := samlresponse.Query1(nil, "//saml:Audience")
		spnamequalifier := samlresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
		fmt.Printf("%s %t %s %s\n", nameidformat, nameid != "", audience, spnamequalifier)
		expected = `urn:oasis:names:tc:SAML:2.0:nameid-format:transient true ` + entityID + ` ` + entityID + "\n"
	}
	stdoutend(t, expected)
}

/*
// TestUnspecifiedNameID tests that the
func TestUnspecifiedNameID(t *testing.T) {
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"}}}
	// BIRK always sends NameIDPolicy/@Format=transient - but respects what the hub sends back - thus we need to fix the request BIRK sends to the hub (WAYFMMISC-940)
	// n := modsset{"birkrequestmods": m["requestmods"]}
	hub := DoRunTestHub(m)
	birk := DoRunTestBirk(m)
	expected := ""
	for _, tp := range []*Testparams{hub, birk} {
		if tp == nil || tp.Resp.StatusCode != 200 {
			continue
		}
		samlresponse := Html2SAMLResponse(tp)
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/saml:AttributeValue")
		fmt.Printf("%s %t %s\n", nameidformat, nameid != "", eptid)
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:transient true {{.eptid}}
`
	}
	stdoutend(t, expected)
}
*/

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
	//    cert := ioutil.ReadFile("testdata/2481cb9e1194df81050c7d22b823540b9442112c.X509Certificate")
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
	var expected string
	stdoutstart()
	// common res for hub and birk
	expected += `cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
eduPersonAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    alum
    member
    student
eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    2
eduPersonEntitlement urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    https://example.com/course101
eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    student
eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonScopedAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    alum@this.is.not.a.valid.idp
    member@this.is.not.a.valid.idp
    student@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    {{.eptid}}
gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton &lt;SamlRequest id=&#34;abc&#34;&gt;abc&lt;/SamlRequest&gt;
mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
norEduPersonLIN urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    123456789
organizationName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Orphanage - home for the homeless
preferredLanguage urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    da
schacCountryOfCitizenship urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    dk
schacDateOfBirth urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    18580824
schacHomeOrganization urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    this.is.not.a.valid.idp
schacHomeOrganizationType urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    urn:mace:terena.org:schac:homeOrganizationType:int:other
schacPersonalUniqueID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234
schacYearOfBirth urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    1858
sn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Cantonsen
`
	res := browse(nil, nil)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestFullAttributesetSP2(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := Md.Internal.MDQ("https://metadata.wayf.dk/PHPh")
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
	spmd, _ := Md.Internal.MDQ("https://metadata.wayf.dk/PHPh")
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
	spmd, _ := Md.Internal.MDQ("https://this.is.not.a.valid.sp")
	overwrite := &overwrites{"Spmd": spmd}
	res := browse(nil, overwrite)
	if res != nil {
		switch *do {
		case "hub", "birk":
			expected = `no common federations
`
		}
	}
	stdoutend(t, expected)
}

func TestSignErrorModifiedContent(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:Issuer", "+ 1234", nil}}}
	res := browse(m, nil)
	if res != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:digest mismatch","err:unable to validate signature"]
`
		}
	}
	stdoutend(t, expected)
}

func TestSamlVulnerability(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name=\"eduPersonPrincipalName\"]/saml:AttributeValue", "- <!--and.a.fake.domain--->", nil}}}
	res := browse(m, nil)
	if res != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:digest mismatch","err:unable to validate signature"]
`
		}
	}
	stdoutend(t, expected)
}

func TestSignErrorModifiedSignature(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./saml:Assertion/ds:Signature/ds:SignatureValue", "+ 1234", nil}}}
	res := browse(m, nil)
	if res != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:crypto/rsa: verification error","err:unable to validate signature"]
`
		}
	}
	stdoutend(t, expected)
}

// TestNoSignatureError tests if the hub and BIRK reacts assertions that are not signed
func TestNoSignatureError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//ds:Signature", "", nil}}}
	res := browse(m, nil)
	if res != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:encryption error"]
`
		}
	}
	stdoutend(t, expected)
}

// TestUnknownKeySignatureError tests if the hub and BIRK reacts on signing with an unknown key
func TestUnknownKeySignatureError(t *testing.T) {
	var expected string
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
	//	_ = DoRunTestBirk(nil)
	if browse(nil, &overwrites{"Privatekey": pk, "Privatekeypw": "-"}) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:crypto/rsa: verification error","err:unable to validate signature"]
`
		}
	}
	stdoutend(t, expected)
}

// TestRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestRequestSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:schema validation failed"]
`
		}
	}
	stdoutend(t, expected)
}

// TestResponseSchemaError tests that the HUB and BIRK reacts on schema errors in responses
func TestResponseSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./@IssueInstant", "isfalse", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:schema validation failed"]
`
		}
	}
	stdoutend(t, expected)
}

// TestNoEPPNError tests that the hub does not accept assertions with no eppn
func TestNoEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:isRequired: eduPersonPrincipalName"]
`
		}
	}
	stdoutend(t, expected)
}

// TestEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func TestEPPNScopingError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil},
		mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue[1]`, "joe@example.com", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:security domain 'example.com' does not match any scopes"]
`
		}
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func TestNoLocalpartInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil},
		mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue[1]`, "@this.is.not.a.valid.idp", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:not a scoped value: @this.is.not.a.valid.idp"]
`
		}
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func TestNoDomainInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{
		mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil},
		mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue[1]`, "joe", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:not a scoped value: joe"]
`
		}
	}
	stdoutend(t, expected)
}

// TestUnknownSPError test how the birk and the hub reacts on requests from an unknown sP
func TestUnknownSPError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./saml:Issuer", "https://www.example.com/unknownentity", nil}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected = `["cause:Metadata not found","err:Metadata not found","key:https://www.example.com/unknownentity","table:HYBRID_EXTERNAL_SP"]
`
		}
	}
	stdoutend(t, expected)
}

// TestUnknownIDPError tests how BIRK reacts on requests to an unknown IdP
// Use the line below for new birkservers
// Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
func TestUnknownIDPError(t *testing.T) {
	var expected string
	stdoutstart()
	switch *do {
	case "hub", "birk":
		m := modsset{"requestmods": mods{mod{"./@Destination", "https://wayf.wayf.dk/unknownentity", nil}}}
		if browse(m, nil) != nil {
			expected = `unknown error
`
		}
	}
	stdoutend(t, expected)
}

func xTestXSW1(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"", "", ApplyXSW1}}}
	if browse(m, nil) != nil {
		switch *do {
		case "hub", "birk":
			expected += `["cause:sql: no rows in result set","err:Metadata not found","key:https://birk.wayf.dk/birk.php/www.example.com/unknownentity","table:HYBRID_EXTERNAL_IDP"]
`
		}
	}
	stdoutend(t, expected)
}

// from https://github.com/SAMLRaider/SAMLRaider/blob/master/src/main/java/helpers/XSWHelpers.java
func ApplyXSW1(xp *goxml.Xp) {
	log.Println(xp.PP())
	assertion := xp.Query(nil, "/samlp:Response[1]/saml:Assertion[1]")[0]
	clonedAssertion := xp.CopyNode(assertion, 1)
	signature := xp.Query(clonedAssertion, "./ds:Signature")[0]
	log.Println(goxml.NewXpFromNode(signature).PP())
	parent, _ := signature.(types.Element).ParentNode()
	parent.RemoveChild(signature)
	defer signature.Free()
	log.Println(goxml.NewXpFromNode(clonedAssertion).PP())
	newSignature := xp.Query(assertion, "ds:Signature[1]")[0]
	newSignature.AddChild(clonedAssertion)
	assertion.(types.Element).SetAttribute("ID", "_evil_response_ID")
	log.Println(xp.PP())
}

func xTestSpeed(t *testing.T) {
	const gorutines = 10
	const iterations = 100000
	for i := 0; i < gorutines; i++ {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < iterations; j++ {
				starttime := time.Now()
				spmd, _ := Md.Internal.MDQ("https://metadata.wayf.dk/PHPh")
				browse(nil, &overwrites{"Spmd": spmd})
				log.Println(i, j, time.Since(starttime).Seconds())
				//runtime.GC()
				//time.Sleep(200 * time.Millisecond)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}
