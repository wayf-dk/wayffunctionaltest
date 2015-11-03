package wayffunctionaltest

import (
    "C"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf
)

// Testparams keeps the info necessary to do a full SAMLRequest -> SAMLResponse roundtrip
// 1st call SSOCreateInitialRequest - then do the possible mods of the request - introduce errors if thats what's going to be tested.
// 2ndly call SSOSendRequest - the result is a SAMLResponse which again can be modified
// 3rdly call SSOSendResponse - and analyze the final resulting SAMLResponse
type Testparams struct {
	spmd, idpmd, hubidpmd, hubspmd, testidpmd, testidpviabirkmd *gosaml.Xp
	cookiejar                                                   map[string]map[string]*http.Cookie
	idpentityID                                                 string
	usescope                                                    bool
	usedoubleproxy                                              bool
	resolv                                                      map[string]string
	initialrequest                                              *gosaml.Xp
	newresponse                                                 *gosaml.Xp
	resp                                                        *http.Response
	responsebody                                                []byte
	err                                                         error
	logrequests, encryptresponse                                bool
	privatekey                                                  string
	privatekeypw                                                string
	certificate	                                                string
	hashalgorithm                                               string
	attributestmt                                               *gosaml.Xp
}

// SSOCreateInitialRequest creates a SAMLRequest given the tp Testparams
func (tp *Testparams) SSOCreateInitialRequest() {

	tp.idpentityID = tp.idpmd.Query1(nil, "@entityID")
	tp.usedoubleproxy = strings.HasPrefix(tp.idpentityID, "https://birk")

	firstidpmd := tp.idpmd
	if !tp.usedoubleproxy {
		firstidpmd = tp.hubidpmd
	}

	tp.initialrequest = gosaml.NewAuthnRequest(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.spmd, firstidpmd)

	// add scoping element if we want to bypass discovery
	if tp.usescope {
		tp.initialrequest.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", tp.idpentityID, nil)
	}
	return
}

// SSOSendRequest sends a SAMLRequest to the @Destination and follows the redirects to the test idp
// If it meets a discovery service it reponds with the testidp
func (tp *Testparams) SSOSendRequest() {
	tp.SSOSendRequest1()
	if tp.err != nil || tp.resp.StatusCode == 500 {
		return
	}
	tp.SSOSendRequest2()
}

func (tp *Testparams) SSOSendRequest1() {

	tp.cookiejar = make(map[string]map[string]*http.Cookie)

	u := gosaml.SAMLRequest2Url(tp.initialrequest)
	// initial request - to hub or birk
	tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
	// Errors from BIRK is 500 + text/plain
	if tp.err != nil || tp.resp.StatusCode == 500 {
		return
	}

	u, _ = tp.resp.Location()

	query := u.Query()
	// we got to a discoveryservice - choose our testidp
	if len(query["return"]) > 0 && len(query["returnIDParam"]) > 0 {
		u, _ = url.Parse(query["return"][0])
		q := u.Query()
		q.Set(query["returnIDParam"][0], tp.idpentityID)
		u.RawQuery = q.Encode()
		tp.resp, _, _ = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
	}
}

func (tp *Testparams) SSOSendRequest2() {
	u, _ := tp.resp.Location()

	// if going via birk we now got a scoped request to the hub
	if tp.usedoubleproxy {
		tp.resp, _, _ = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
		u, _ = tp.resp.Location()
	}

	// We still expect to be redirected
	// if we are not at our final IdP something is rotten

	testidp, _ := url.Parse(tp.testidpmd.Query1(nil, "@entityID"))
	if u.Host != testidp.Host {
		// Errors from HUB is 302 to https://wayf.wayf.dk/displayerror.php ... which is a 500 with html content
		u, _ = tp.resp.Location()
		tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
		return
	}

	// get the SAMLRequest
	query := u.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	authnrequest := gosaml.NewXp(gosaml.Inflate(req))

	// create a response
	tp.newresponse = gosaml.NewResponse(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.testidpmd, tp.hubspmd, authnrequest, tp.attributestmt)

	// and sign it
	assertion := tp.newresponse.Query(nil, "saml:Assertion[1]")[0]

	// use cert to calculate key name
	tp.newresponse.Sign(assertion, tp.privatekey, tp.privatekeypw, tp.certificate, tp.hashalgorithm)

	if tp.encryptresponse {
	    _, publickey, _, _ := tp.hubspmd.PublicKeyInfo("encryption")
	    tp.newresponse.Encrypt(assertion, publickey)
	}
	return
}

// SSOSendResponse POSTs a SAML response and follows the POSTs back to the orignal requester
// It answers yes to the possible WAYF consent page it meets along the way
// If it encounters an error page it returns immediately
func (tp *Testparams) SSOSendResponse() {
	tp.SSOSendResponse1()
	tp.SSOSendResponse2()
}

func (tp *Testparams) SSOSendResponse1() {
	// and POST it to the hub
	acs := tp.newresponse.Query1(nil, "@Destination")
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tp.newresponse.X2s())))

	u, _ := url.Parse(acs)
	tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "POST", data.Encode(), tp.cookiejar)

	if u, _ = tp.resp.Location(); u == nil {
		return
	}

	if tp.resp.StatusCode == 500 {
		return
	}

	if strings.Contains(u.Path, "displayerror.php") {
		tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
		return
	}
	// and now for some consent
	if strings.Contains(u.Path, "getconsent.php") {
		u.RawQuery = u.RawQuery + "&yes=1"
		tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
	}
	tp.newresponse = gosaml.Html2SAMLResponse(tp.responsebody)
}

func (tp *Testparams) SSOSendResponse2() {
	// if going via birk we have to POST it again
	if tp.usedoubleproxy {
		tp.SSOSendResponse1()
	}
	// last POST doesn't actually get POSTed - we don't have a real SP ...
	return
}

// SendRequest sends a http request - GET or POST using the supplied url, server, method and cookies
// It updates the cookies and returns a http.Response and a posssible response body and error
// The server parameter contains the dns name of the actual server, which should respond to the host part of the url
func (tp *Testparams) sendRequest(url *url.URL, server, method, body string, cookies map[string]map[string]*http.Cookie) (resp *http.Response, responsebody []byte, err error) {
	if server == "" {
		server = url.Host + ":443"
	}
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
	req, err := http.NewRequest(method, url.String(), payload)

	for _, cookie := range cookies[host] {
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
		return
	}

	location, _ := resp.Location()
	loc := ""
	if location != nil {
		loc = location.Host + location.Path
	}
	if tp.logrequests {
		log.Printf("%-4s %-70s %s %-15s %s\n", req.Method, server+req.URL.Path, resp.Proto, resp.Status, loc)
	}
	setcookies := resp.Cookies()
	for _, cookie := range setcookies {
		if cookies[url.Host] == nil {
			cookies[url.Host] = make(map[string]*http.Cookie)
		}
		cookies[url.Host][cookie.Name] = cookie
	}

	// We can't get to the body if we got a redirect pseudo error above
	if err == nil {
		responsebody, err = ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
	}
	// we need to nullify the damn redirec-not-allowed error from above
	err = nil
	return
}
