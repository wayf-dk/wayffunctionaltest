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
	Spmd, Idpmd, Hubidpmd, Hubspmd, Testidpmd, Testidpviabirkmd *gosaml.Xp
	Cookiejar                                                   map[string]map[string]*http.Cookie
	IdpentityID                                                 string
	Usescope                                                    bool
	Usedoubleproxy                                              bool
	Resolv                                                      map[string]string
	Initialrequest                                              *gosaml.Xp
	Newresponse                                                 *gosaml.Xp
	Resp                                                        *http.Response
	Responsebody                                                []byte
	Err                                                         error
	Logrequests, Encryptresponse                                bool
	Privatekey                                                  string
	Privatekeypw                                                string
	Certificate	                                                string
	Hashalgorithm                                               string
	Attributestmt                                               *gosaml.Xp
}

// SSOCreateInitialRequest creates a SAMLRequest given the tp Testparams
func (tp *Testparams) SSOCreateInitialRequest() {

	tp.IdpentityID = tp.Idpmd.Query1(nil, "@entityID")
	tp.Usedoubleproxy = strings.HasPrefix(tp.IdpentityID, "https://birk")

	firstidpmd := tp.Idpmd
	if !tp.Usedoubleproxy {
		firstidpmd = tp.Hubidpmd
	}

	tp.Initialrequest = gosaml.NewAuthnRequest(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.Spmd, firstidpmd)

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
		return
	}
	tp.SSOSendRequest2()
}

func (tp *Testparams) SSOSendRequest1() {

	tp.Cookiejar = make(map[string]map[string]*http.Cookie)

	u := gosaml.SAMLRequest2Url(tp.Initialrequest)
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
		q.Set(query["returnIDParam"][0], tp.IdpentityID)
		u.RawQuery = q.Encode()
		tp.Resp, _, _ = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
	}
}

func (tp *Testparams) SSOSendRequest2() {
	u, _ := tp.Resp.Location()

	// if going via birk we now got a scoped request to the hub
	if tp.Usedoubleproxy {
		tp.Resp, _, _ = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
		u, _ = tp.Resp.Location()
	}

	// We still expect to be redirected
	// if we are not at our final IdP something is rotten

	testidp, _ := url.Parse(tp.Testidpmd.Query1(nil, "@entityID"))
	if u.Host != testidp.Host {
		// Errors from HUB is 302 to https://wayf.wayf.dk/displayerror.php ... which is a 500 with html content
		u, _ = tp.Resp.Location()
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
		return
	}

	// get the SAMLRequest
	query := u.Query()
	req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	authnrequest := gosaml.NewXp(gosaml.Inflate(req))

	// create a response
	tp.Newresponse = gosaml.NewResponse(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.Testidpmd, tp.Hubspmd, authnrequest, tp.Attributestmt)

	// and sign it
	assertion := tp.Newresponse.Query(nil, "saml:Assertion[1]")[0]

	// use cert to calculate key name
	tp.Newresponse.Sign(assertion, tp.Privatekey, tp.Privatekeypw, tp.Certificate, tp.Hashalgorithm)

	if tp.Encryptresponse {
	    _, publickey, _, _ := tp.Hubspmd.PublicKeyInfo("encryption")
	    tp.Newresponse.Encrypt(assertion, publickey)
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
	acs := tp.Newresponse.Query1(nil, "@Destination")
	data := url.Values{}
	data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tp.Newresponse.X2s())))

	u, _ := url.Parse(acs)
	tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "POST", data.Encode(), tp.Cookiejar)

	if u, _ = tp.Resp.Location(); u == nil {
		return
	}

	if tp.Resp.StatusCode == 500 {
		return
	}

	if strings.Contains(u.Path, "displayerror.php") {
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
		return
	}
	// and now for some consent
	if strings.Contains(u.Path, "getconsent.php") {
		u.RawQuery = u.RawQuery + "&yes=1"
		tp.Resp, tp.Responsebody, tp.Err = tp.sendRequest(u, tp.Resolv[u.Host], "GET", "", tp.Cookiejar)
	}
	tp.Newresponse = gosaml.Html2SAMLResponse(tp.Responsebody)
}

func (tp *Testparams) SSOSendResponse2() {
	// if going via birk we have to POST it again
	if tp.Usedoubleproxy {
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
		log.Fatal(err)
	}

	location, _ := resp.Location()
	loc := ""
	if location != nil {
		loc = location.Host + location.Path
	}
	if tp.Logrequests {
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

func ApplyMods(xp *gosaml.Xp, m mods) {
    for _, change := range m {
        if change.value == "" {
	        for _, element := range xp.Query(nil, change.path) {
	            xp.UnlinkNode(element)
	        }
	    } else if strings.HasPrefix(change.value, "+ ") {
	        for _, element := range xp.Query(nil, change.path) {
                value := xp.NodeGetContent(element)
                xp.NodeSetContent(element, strings.Fields(change.value)[1] + value)
	        }
        } else {
            xp.QueryDashP(nil, change.path, change.value, nil)
        }
        //log.Println(xp.Pp())
    }
}


func DoRunTestHub(m modsset) (tp *Testparams) {
    tp = Newtp()
    defer xxx(tp.Logrequests)
    ApplyMods(tp.Attributestmt, m["attributemods"])
    tp.SSOCreateInitialRequest()
    ApplyMods(tp.Initialrequest, m["requestmods"])
    tp.SSOSendRequest()
    if tp.Resp.StatusCode == 500 {
        response := gosaml.NewHtmlXp(tp.Responsebody)
        fmt.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))
        return
    }
    ApplyMods(tp.Newresponse, m["responsemods"])
    tp.SSOSendResponse()
    if tp.Resp.StatusCode == 500 {
        response := gosaml.NewHtmlXp(tp.Responsebody)
        fmt.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))
        return
    }
    return
}

func DoRunTestBirk(m modsset) (tp *Testparams) {
	tp = Newtp()
    defer xxx(tp.Logrequests)
	tp.Idpmd = tp.Testidpviabirkmd

    ApplyMods(tp.Attributestmt, m["attributemods"])
    tp.SSOCreateInitialRequest()
    ApplyMods(tp.Initialrequest, m["requestmods"])
    tp.SSOSendRequest1()
    if tp.Resp.StatusCode == 500 {
    	fmt.Println(strings.SplitN(string(tp.Responsebody), " ", 2)[1])
    	return
    }
    authnrequest := gosaml.Url2SAMLRequest(tp.Resp.Location())
    ApplyMods(authnrequest, m["birkrequestmods"])
    tp.Resp.Header.Set("Location", gosaml.SAMLRequest2Url(authnrequest).String())
    if tp.Resp.StatusCode == 500 {
    	fmt.Println(strings.SplitN(string(tp.Responsebody), " ", 2)[1])
    	return
    }
    tp.SSOSendRequest2()
    tp.SSOSendResponse1()
    ApplyMods(tp.Newresponse, m["responsemods"])
    tp.SSOSendResponse2()
    if tp.Resp.StatusCode == 500 {
    	fmt.Println(strings.SplitN(string(tp.Responsebody), " ", 2)[1])
    	return
    }
    return
}

func xxx(really bool) {
    if really {
        log.Println()
    }
}

