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
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/gosaml"
  . "github.com/y0ssar1an/q"
)

const (
	samlSchema = "src/github.com/wayf-dk/goxml/schemas/saml-schema-protocol-2.0.xsd"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf
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
		Usescope                                           bool
		Usedoubleproxy                                     bool
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

// SSOCreateInitialRequest creates a SAMLRequest given the tp Testparams
func (tp *Testparams) SSOCreateInitialRequest() {

	tp.IdpentityID = tp.Idpmd.Query1(nil, "@entityID")

	tp.Initialrequest = gosaml.NewAuthnRequest(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.Spmd, tp.Firstidpmd)
	// add scoping element if we want to bypass discovery
	if tp.Usescope {
		tp.Initialrequest.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", tp.IdpentityID, nil)
	}
	return
}

// SSOSendRequest sends a SAMLRequest to the @Destination and follows the redirects to the test idp
// If it meets a discovery service it reponds with the testidp
func (tp *Testparams) SSOSendRequest() {
	tp.SSOSendRequest1()
	if tp.Err != nil || tp.Resp.StatusCode == 500 {
		if u, _ := tp.Resp.Location(); u != nil {
			if strings.Contains(u.Path, "displayerror.php") {
				tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
				if tp.Logxml {
					log.Println("Displayerror:", string(tp.Responsebody))
				}
				return
			}
		}
	}
	tp.SSOSendRequest2()
}

// SSOSendRequest1 does the 1st part of sending the request, handles the discovery service if needed
func (tp *Testparams) SSOSendRequest1() {

	if tp.Logxml {
		log.Println(tp)
		log.Println("initialrequest:", tp.Initialrequest.Doc.Dump(true))
	}
	u, _ := gosaml.SAMLRequest2Url(tp.Initialrequest, "", "", "")

	// initial request - to hub or birk
	tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
	// Errors from BIRK is 500 + text/plain
	if tp.Err != nil || tp.Resp.StatusCode == 500 {
		return
	}

	u, _ = tp.Resp.Location()

	query := u.Query()
	// we got to a discoveryservice - choose our testidp
	if len(query["return"]) > 0 && len(query["returnIDParam"]) > 0 {
		u, _ = url.Parse(query["return"][0])
		q := u.Query()
		q.Set(query["returnIDParam"][0], tp.DSIdpentityID)
		u.RawQuery = q.Encode()
		tp.Resp, _, _ = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
	}
}

// SSOSendRequest2 does the 2nd part of sending the request to the final IdP.
// Creates the response and signs and optionally encrypts it
func (tp *Testparams) SSOSendRequest2() {
	u, _ := tp.Resp.Location()

	// if going via birk we now got a scoped request to the hub
	if tp.Usedoubleproxy {

		if tp.Logxml {
			query := u.Query()
			req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
			authnrequest := goxml.NewXp(string(gosaml.Inflate(req)))
			log.Println("birkrequest", authnrequest.Doc.Dump(true))
		}

		tp.Resp, tp.Responsebody, _ = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
		u, _ = tp.Resp.Location()
	}

	// We still expect to be redirected
	// if we are not at our final IdP something is rotten

	eid := tp.Idpmd.Query1(nil, "@entityID")
	idp, _ := url.Parse(eid)
	if u.Host != idp.Host {
		//log.Println("u.host != idp.Host", u, idp)
		// Errors from HUB is 302 to https://wayf.wayf.dk/displayerror.php ... which is a 500 with html content
		u, _ = tp.Resp.Location()
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
		return
	}

	// get the SAMLRequest
	query := u.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	authnrequest := goxml.NewXp(string(gosaml.Inflate(req)))

	if tp.Logxml {
		log.Println("idprequest", authnrequest.Doc.Dump(true))
	}

	// create a response
	tp.Newresponse = gosaml.NewResponse(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.Idpmd, tp.Hubspmd, authnrequest, tp.Attributestmt)

	// and sign it
	assertion := tp.Newresponse.Query(nil, "saml:Assertion[1]")[0]

	// use cert to calculate key name
	err := tp.Newresponse.Sign(assertion.(types.Element), tp.Privatekey, tp.Privatekeypw, tp.Certificate, tp.Hashalgorithm)
	if err != nil {
	    log.Println("Error from sign ..", tp.Privatekey, tp.Privatekeypw);
		log.Fatal(err)
	}

	if tp.Logxml {
		log.Println("response", tp.Newresponse.Doc.Dump(true))
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

       	ea := goxml.NewXp(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
		tp.Newresponse.Encrypt(assertion.(types.Element), publickey, ea)
		tp.Encryptresponse = false // for now only possible for idp -> hub

        if tp.Logxml {
            log.Println("response", tp.Newresponse.Doc.Dump(true))
        }
	}

	return
}

// SSOSendResponse POSTs a SAML response and follows the POSTs back to the orignal requester
// It answers yes to the possible WAYF consent page it meets along the way
// If it encounters an error page it returns immediately
func (tp *Testparams) SSOSendResponse() {
	acs := tp.Newresponse.Query1(nil, "@Destination")
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tp.Newresponse.Doc.Dump(false))))

	u, _ := url.Parse(acs)
	tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "POST", data.Encode(), tp.Cookiejar)

	if tp.Resp.StatusCode == 500 {
		return
	}
    Q(string(tp.Responsebody), tp.Resp.Header)
	if u, _ = tp.Resp.Location(); u != nil {
		if strings.Contains(u.Path, "displayerror.php") {
			tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
			if tp.Logxml {
				log.Println("Displayerror:", string(tp.Responsebody))
			}
			return
		}
		// and now for some consent
		if strings.Contains(u.Path, "getconsent.php") {
			u.RawQuery = u.RawQuery + "&yes=1"
			tp.ConsentGiven = true
			tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
			u, _ = tp.Resp.Location()
		}
	}

	tp.Newresponse = gosaml.Html2SAMLResponse(tp.Responsebody)
	if tp.Newresponse.Query1(nil, "/samlp:Response") == "" { // is it non-displayerror.php error find out which
        if tp.Logxml {
            log.Println("response", string(tp.Responsebody))
        }
	    tp.Resp.StatusCode = 500
	    tp.Responsebody = []byte(`<html><body><a id="errormsg" href="http://www.example.com">unknown error</a></body></html>`) // fake an error from displayerror.php
		return
	} else {
        if tp.Logxml {
            log.Println("response", tp.Newresponse.Doc.Dump(true))
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
	Q(req)

	resp, err = client.Do(req)
	if err != nil && !strings.HasSuffix(err.Error(), "redirect-not-allowed") {
	    Q(err, resp)
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
		response := goxml.NewHtmlXp(string(responsebody))
		samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
		if samlbase64 != "" {
			samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
			samlresponse := goxml.NewXp(string(samlxml))
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
	//log.Printf("%+v\n", m)
	//log.Println(xp.X2s())
	for _, change := range m {
	    if change.function != nil {
	        change.function(xp)
	    } else if change.value == "" {
			//log.Printf("changeval: '%s'\n", change.value)
			for _, element := range xp.Query(nil, change.path) {
				//log.Printf("unlink: %s\n", change.path)
				parent, _ := element.ParentNode();
				parent.RemoveChild(element)
			}
		} else if strings.HasPrefix(change.value, "+ ") {
			for _, element := range xp.Query(nil, change.path) {
				value := element.NodeValue()
				element.SetNodeValue(strings.Fields(change.value)[1]+value)
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
	if *dokrib {
		return DoRunTestKrib(m, overwrite)
	}
	if !*dohub {
		return
	}
	tp = Newtp(overwrite)
	defer xxx(tp.Trace)
	ApplyMods(tp.Attributestmt, m["attributemods"])
	tp.SSOCreateInitialRequest()
	ApplyMods(tp.Initialrequest, m["requestmods"])

	tp.SSOSendRequest()
	if tp.Resp.StatusCode == 500 {
		response := goxml.NewHtmlXp(string(tp.Responsebody))
		fmt.Println(strings.Trim(response.Query1(nil, `//a[@id="errormsg"]/text()`), "\n "))
		return
	}
	ApplyMods(tp.Newresponse, m["responsemods"])
	tp.SSOSendResponse()
	if tp.Resp.StatusCode == 500 {
		response := goxml.NewHtmlXp(string(tp.Responsebody))
		fmt.Println(strings.Trim(response.Query1(nil, `//a[@id="errormsg"]/text()`), "\n "))
		return
	}

    err := ValidateSignature(tp.Hubidpmd, tp.Newresponse)
    if err != nil {
        fmt.Printf("signature errors: %s\n", err)
    }

	return
}

// DoRunTestBirk runs a test on the hub - applying the necessary modifications on the way
// Returns a *Testparams which can be analyzed
func DoRunTestBirk(m modsset, overwrite *Testparams) (tp *Testparams) {
	if !*dobirk {
		return
	}
	tp = Newtp(overwrite)
	defer xxx(tp.Trace)
	tp.Firstidpmd = tp.Birkmd
	tp.Usedoubleproxy = true

	ApplyMods(tp.Attributestmt, m["attributemods"])
	tp.SSOCreateInitialRequest()
	ApplyMods(tp.Initialrequest, m["requestmods"])
	//    log.Println(tp.Initialrequest.Pp())
	tp.SSOSendRequest1()
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.Trim(strings.SplitN(string(tp.Responsebody), " ", 2)[1], "\n "))
		return
	}
	authnrequest := gosaml.Url2SAMLRequest(tp.Resp.Location())
	ApplyMods(authnrequest, m["birkrequestmods"])
	//    log.Println(authnrequest.Pp())
	u, _ := gosaml.SAMLRequest2Url(authnrequest, "", "", "")
	tp.Resp.Header.Set("Location", u.String())
	tp.SSOSendRequest2()
	// pt. after signing - remember to have a before as well

	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.SplitN(string(tp.Responsebody), " ", 2)[1])
		return
	}
	tp.SSOSendResponse()
	if tp.Resp.StatusCode == 500 {
		response := goxml.NewHtmlXp(string(tp.Responsebody))
		fmt.Println(strings.Trim(response.Query1(nil, `//a[@id="errormsg"]/text()`), "\n "))
		return
	}
	ApplyMods(tp.Newresponse, m["responsemods"])
	tp.SSOSendResponse()
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.Trim(strings.SplitN(string(tp.Responsebody), " ", 2)[1], "\n "))
		return
	}

    err := ValidateSignature(tp.Firstidpmd, tp.Newresponse)
    if err != nil {
        fmt.Printf("signature errors: %s\n", err)
    }

	return
}

// DoRunTestKrib
func DoRunTestKrib(m modsset, overwrite *Testparams) (tp *Testparams) {
	if !*dokrib {
		return
	}
	tp = Newtp(overwrite)
	defer xxx(tp.Trace)
	tp.Usedoubleproxy = true

	ApplyMods(tp.Attributestmt, m["attributemods"])
	tp.SSOCreateInitialRequest()
	ApplyMods(tp.Initialrequest, m["requestmods"])
	//    log.Println(tp.Initialrequest.Pp())
	tp.SSOSendRequest1()
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.TrimSpace(string(tp.Responsebody)))
		return
	}
	authnrequest := gosaml.Url2SAMLRequest(tp.Resp.Location())
	ApplyMods(authnrequest, m["birkrequestmods"])
	u, _ := gosaml.SAMLRequest2Url(authnrequest, "", "", "")
	tp.Resp.Header.Set("Location", u.String())
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.TrimSpace(string(tp.Responsebody)))
		return
	}
	tp.SSOSendRequest2()
	if tp.Newresponse == nil {
		log.Panic(string(tp.Responsebody))
	}
	tp.SSOSendResponse()
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.TrimSpace(string(tp.Responsebody)))
		return
	}

	tp.SSOSendResponse()
	if tp.Resp.StatusCode == 500 {
		fmt.Println(strings.TrimSpace(string(tp.Responsebody)))
		return
	}
	if tp.Logxml {
		log.Println("final response", tp.Newresponse.Doc.Dump(true))
	}
	return
}

// Html2SAMLResponse extracts the SAMLResponse from a html document
func Html2SAMLResponse(tp *Testparams) (samlresponse *goxml.Xp) {
	response := goxml.NewHtmlXp(string(tp.Responsebody))
	samlbase64 := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
	samlxml, _ := base64.StdEncoding.DecodeString(samlbase64)
	samlresponse = goxml.NewXp(string(samlxml))
	if _, err := samlresponse.SchemaValidate(samlSchema); err != nil {
		fmt.Println("SchemaError")
	}

	certs := tp.Firstidpmd.Query(nil, `//md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
	if len(certs) == 0 {
		fmt.Printf("Could not find signing cert for: %s", tp.Firstidpmd.Query1(nil, "/@entityID"))
		log.Printf("Could not find signing cert for: %s", tp.Firstidpmd.Query1(nil, "/@entityID"))
	}

	_, pub, _ := gosaml.PublicKeyInfo(certs[0].NodeValue())
	assertion := samlresponse.Query(nil, "saml:Assertion[1]")
	if assertion == nil {
		fmt.Println("no assertion found")
	}
	if err := samlresponse.VerifySignature(assertion[0].(types.Element), pub); err != nil {
		fmt.Printf("SignatureVerificationError %s", err)
	}
	return
}

func ValidateSignature(md, xp *goxml.Xp) (err error) {

    //no ds:Object in signatures `./md:IDPSSODescriptor/md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`
//    certificates := md.Query(nil, gosaml.IdpCertQuery)
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
    verified := 0
    signerrors := []error{}
    for _, certificate := range certificates {
        var key *rsa.PublicKey
        _, key, err = gosaml.PublicKeyInfo(certificate.NodeValue())

        if err != nil {
            return
       }

        for _, signature := range signatures {
            signerror := xp.VerifySignature(signature.(types.Element), key)
            if signerror != nil {
                signerrors = append(signerrors, signerror)
            } else {
                verified++
            }
        }
    }
    if verified == 0 || verified != len(signatures) {
        errorstring := ""
        delim := ""
        for _, e := range signerrors {
            errorstring += e.Error() + delim
            delim = ", "
        }
        err = fmt.Errorf("%s unable to validate signature: %s", destination, errorstring)
        return
    }
    return
}

func xxx(really bool) {
	if really {
		log.Println()
	}
}
