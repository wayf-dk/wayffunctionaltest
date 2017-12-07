// Wayffunctionaltest is a library that makes it easy/easier to make tests for
// the WAYF hub and BIRK hub.
// It 'contains' an SP, an IdP and a browser that drives the SAML request/response flow
// thru the hubs. During the flow the requests/responses can be modified to test
// specific behavior of the hubs - eg. introducing errors.
// The actual tests are written as tests for the package - (mis)using the Go testing framework
// to do the testing minuteae.
// It depends on wayf-dk/gosaml for doing SAML things.
package wayffunctionaltest

import (
	"C"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/y0ssar1an/q"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf
	_ = q.Q
)

type (

	// Testparams keeps the info necessary to do a full SAMLRequest -> SAMLResponse roundtrip
	// 1st call SSOCreateInitialRequest - then do the possible mods of the request - introduce errors if thats what's going to be tested.
	// 2ndly call SSOSendRequest - the result is a SAMLResponse which again can be modified
	// 3rdly call SSOSendResponse - and analyze the final resulting SAMLResponse
	Testparams struct {
		Spmd, Idpmd, Hubidpmd, Hubspmd, Birkmd, Firstidpmd *goxml.Xp
		Cookiejar                                          map[string]map[string]*http.Cookie
		IdpentityID                                        string
		DSIdpentityID                                      string
		Resolv                                             map[string]string
		Initialrequest                                     *goxml.Xp
		Newresponse                                        *goxml.Xp
		Resp                                               *http.Response
		Responsebody                                       []byte
		Err                                                error
		Trace, Logxml, Encryptresponse                     bool
		Privatekey                                         string
		Privatekeypw                                       string
		Certificate                                        string
		Hashalgorithm                                      string
		Attributestmt                                      *goxml.Xp
		Hub                                                bool
		Krib                                               bool
		Birk                                               bool
		Env                                                string
		ConsentGiven                                       bool
	}

	testrun func(modsset, *Testparams) *Testparams
)

// Does what the browser does follow redirects and POSTs and displays errors
func browse(m modsset, overwrite *Testparams) (tp *Testparams) {
	tp = Newtp(overwrite)
	stage := map[string]string{"hub": "wayf.wayf.dk", "birk": "birk.wayf.dk", "birk2": "wayf.wayf.dk", "krib": "krib.wayf.dk"}[*do]

	ApplyMods(tp.Attributestmt, m["attributemods"])
	//q.Q("tp", tp)
	tp.Initialrequest, _ = gosaml.NewAuthnRequest(nil, tp.Spmd, tp.Firstidpmd, tp.IdpentityID)
	ApplyMods(tp.Initialrequest, m["requestmods"])
	u, _ := gosaml.SAMLRequest2Url(tp.Initialrequest, "", "", "", "")

	// when to stop
	finalDestination, _ := url.Parse(tp.Initialrequest.Query1(nil, "./@AssertionConsumerServiceURL"))
	redirects := 7
	method := "GET"
	body := ""
	for {
		redirects--
		if redirects == 0 {
			return
		}
		if method == "POST" {
			acs := tp.Newresponse.Query1(nil, "@Destination")
			u, _ = url.Parse(acs)
			//q.Q(u, finalDestination)
			if u.Host == finalDestination.Host {
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
		}

		//q.Q("u", method, redirects, u)
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], method, body, tp.Cookiejar)
		tp.Resp.TLS = nil
		tp.Resp.Body = nil
		//q.Q("resp", tp, tp.Err, tp.Resp, string(tp.Responsebody))
		if u, _ = tp.Resp.Location(); u != nil { // we don't care about the StatusCode - Location means redirect
			if tp.Err == nil { // for now dont' care about StatusCode
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
			if u.Host != "this.is.not.a.valid.idp" {
				method = "GET"
				body = ""
			} else {
				tp.newresponse(u)
				method = "POST"
			}
			continue
		}
		if tp.Resp.StatusCode == 500 {
			error := ""
			if tp.Resp.Header.Get("content-type") == "text/html" { // hub errors
				error = goxml.NewHtmlXp(tp.Responsebody).Query1(nil, `//a[@id="errormsg"]/text()`)
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

	if tp.Logxml {
		log.Println("idprequest", authnrequest.PP())
	}

	// create a response
	tp.Newresponse = gosaml.NewResponse(tp.Idpmd, tp.Hubspmd, authnrequest, tp.Attributestmt)

	// and sign it
	assertion := tp.Newresponse.Query(nil, "saml:Assertion[1]")[0]

	// use cert to calculate key name
	before := tp.Newresponse.Query(assertion, "*[2]")[0]
	err := tp.Newresponse.Sign(assertion.(types.Element), before.(types.Element), []byte(tp.Privatekey), []byte(tp.Privatekeypw), tp.Certificate, tp.Hashalgorithm)
	if err != nil {
		log.Println("Error from sign ..", tp.Privatekey, tp.Privatekeypw)
		log.Fatal(err)
	}

	if tp.Logxml {
		log.Println("response", tp.Newresponse.PP())
	}

	if tp.Encryptresponse {

		certs := tp.Hubspmd.Query(nil, `//md:KeyDescriptor[@use="encryption" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
		if len(certs) == 0 {
			fmt.Errorf("Could not find encryption cert for: %s", tp.Hubspmd.Query1(nil, "/@entityID"))
		}

		_, publickey, _ := gosaml.PublicKeyInfo(certs[0].NodeValue())

		if tp.Env == "xdev" {
			cert, err := ioutil.ReadFile(*testcertpath)
			pk, err := x509.ParseCertificate(cert)
			if err != nil {
				return
			}
			publickey = pk.PublicKey.(*rsa.PublicKey)
		}

		ea := goxml.NewXpFromString(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
		tp.Newresponse.Encrypt(assertion.(types.Element), publickey, ea)
		tp.Encryptresponse = false // for now only possible for idp -> hub

		if tp.Logxml {
			log.Println("response", tp.Newresponse.PP())
		}
	}
}

// SendRequest sends a http request - GET or POST using the supplied url, server, method and cookies
// It updates the cookies and returns a http.Response and a posssible response body and error
// The server parameter contains the dns name of the actual server, which should respond to the host part of the url
func (tp *Testparams) sendRequest(url *url.URL, server, method, body string, cookies map[string]map[string]*http.Cookie) (resp *http.Response, responsebody []byte, err error) {
	if server == "" {
		server = url.Host
	}
	server += ":443"

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		Dial:               func(network, addr string) (net.Conn, error) { return net.Dial("tcp", server) },
		DisableCompression: true,
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("redirect-not-allowed") },
	}

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
		debug.PrintStack()
		log.Fatalln("client.do", err)
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
	//log.Printf("applyMOds %+v\n", m)
	//log.Println(xp.X2s())
	for _, change := range m {
		if change.function != nil {
			change.function(xp)
		} else if change.value == "" {
			//log.Printf("changeval: '%s'\n", change.value)
			for _, element := range xp.Query(nil, change.path) {
				//log.Printf("unlink: %s\n", change.path)
				parent, _ := element.ParentNode()
				parent.RemoveChild(element)
			}
		} else if strings.HasPrefix(change.value, "+ ") {
			for _, element := range xp.Query(nil, change.path) {
				value := element.NodeValue()
				element.SetNodeValue(strings.Fields(change.value)[1] + value)
			}
		} else {
			xp.QueryDashP(nil, change.path, change.value, nil)
		}
	}
	//log.Println(xp.X2s())
}

// DoRunTestHub runs a test on the hub - applying the necessary modifications on the way.
// Returns a *Testparams which can be analyzed
func DoRunTestHub(m modsset, overwrite *Testparams) (tp *Testparams) {
	if !dohub {
		return
	}
	tp = browse(m, overwrite)
	return
}

func DoRunTestBirk(m modsset, overwrite *Testparams) (tp *Testparams) {
	if !dobirk {
		return
	}
	tp = browse(m, overwrite)
	return
}

func DoRunTestBirk2(m modsset, overwrite *Testparams) (tp *Testparams) {
	if !dobirk2 {
		return
	}
	tp = browse(m, overwrite)
	return
}

// DoRunTestKrib
func DoRunTestKrib(m modsset, overwrite *Testparams) (tp *Testparams) {
	if dobirk2 {
		return DoRunTestBirk2(m, overwrite)
	}
	if !dokrib {
		return
	}
	tp = browse(m, overwrite)
	return
}

func ValidateSignature(md, xp *goxml.Xp) (err error) {
	certificates := md.Query(nil, `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
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

	err = gosaml.VerifySign(xp, certificates, signatures)
	return
}
