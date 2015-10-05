package wayffunctionaltest

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/wayf-dk/gosaml"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	attributestmt = []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                >
        <saml:AttributeStatement>
            <saml:Attribute Name="cn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonEntitlement"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/kanja/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/orphanage/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/vo/admin</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="organizationName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF Where Are You From</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="preferredLanguage"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">da</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="mail"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">freek@wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrincipalName"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="gn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="sn"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonPrimaryAffiliation"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonAssurance"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="schacHomeOrganization"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="schacHomeOrganizationType"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="eduPersonTargetedID"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF-DK-a462971438f09f28b0cf806965a5b5461376815b</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.3"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/kanja/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/orphanage/admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string">https://wayf.dk/vo/admin</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF Where Are You From</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.39"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">da</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">freek@wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">gikcaswid@orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.42"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Mads Freek</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:2.5.4.4"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">Petersen</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">orphanage.wayf.dk</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:NRENAffiliate</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
                            NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                            >
                <saml:AttributeValue xsi:type="xs:string">WAYF-DK-a462971438f09f28b0cf806965a5b5461376815b</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </samlp:Response>`)
)

type Testparams struct{
    spmd, idpmd, hubmd, testidpmd *gosaml.Xp
    cookiejar map[string]map[string]*http.Cookie
    idpentityID string
    usescope bool
    usedoubleproxy bool
    resolv map[string]string
    initialrequest *gosaml.Xp
    newresponse *gosaml.Xp
    resp *http.Response
    responsebody []byte
    err error
    logrequests bool
}

func (tp *Testparams) SSOCreateInitialRequest() {

	tp.idpentityID = tp.idpmd.Query1(nil, "@entityID")
	tp.usedoubleproxy = strings.HasPrefix(tp.idpentityID, "https://birk")

    firstidpmd := tp.idpmd
	if !tp.usedoubleproxy {
		firstidpmd = tp.hubmd
	}

	tp.initialrequest = gosaml.NewAuthnRequest(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.spmd, firstidpmd)

    // add scoping element if we want to bypass discovery
	if tp.usescope {
		tp.initialrequest.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", tp.idpentityID, nil)
	}
	return
}

func (tp *Testparams) SSOSendRequest() {

	tp.cookiejar = make(map[string]map[string]*http.Cookie)
	samlrequest := base64.StdEncoding.EncodeToString(gosaml.Deflate(tp.initialrequest.Pp()))

	u, _ := url.Parse(tp.initialrequest.Query1(nil, "@Destination"))
	q := u.Query()
	q.Set("SAMLRequest", samlrequest)
	u.RawQuery = q.Encode()

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


    // if going via birk we now got a scoped request to the hub
	if tp.usedoubleproxy {
		u, _ = tp.resp.Location()
		tp.resp, _, _ = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
	}

    // We still expect to be redirected
	u, _ = tp.resp.Location()
	// if we are not at our final IdP something is rotten
	if u.Host != "this.is.not.a.valid.idp" {
		// Errors from HUB is 302 to https://wayf.wayf.dk/displayerror.php ... which is a 500 with html content
		u, _ = tp.resp.Location()
		tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
		return
	}

    // get the SAMLRequest
	query = u.Query()
    req, _ := base64.StdEncoding.DecodeString(query["SAMLRequest"][0])
	authnrequest := gosaml.NewXp(gosaml.Inflate(req))
	sourceresponse := gosaml.NewXp(attributestmt)

    // create a response
    tp.newresponse = gosaml.NewResponse(gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}, tp.testidpmd, tp.hubmd, authnrequest, sourceresponse)

    // and sign it
    assertion := tp.newresponse.Query(nil, "saml:Assertion[1]")[0]
    privatekey, _ := ioutil.ReadFile("/etc/ssl/wayf/signing/this.is.not.a.valid.idp.key")

	tp.newresponse.Sign(assertion, string(privatekey), os.Getenv("PW"),  "sha1")

    return
}

func (tp *Testparams) SSOSendResponse() {

    // and POST it to the hub
	acs := tp.newresponse.Query1(nil, "@Destination")
    data := url.Values{}
    data.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tp.newresponse.Pp())))

    u, _ := url.Parse(acs)
    tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "POST", data.Encode(), tp.cookiejar)

    u, _ = tp.resp.Location()

    if strings.Contains(u.Path, "displayerror.php") {
        tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
        return
    }
    // and now for some consent
    if strings.Contains(u.Path, "getconsent.php") {
        u.RawQuery = u.RawQuery + "&yes=1"
        tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "GET", "", tp.cookiejar)
    }

    // if going via birk we have to POST it again
    if tp.usedoubleproxy {
        response := gosaml.NewHtmlXp(tp.responsebody)
        action := response.Query1(nil, "//@action")
        responsebodyvalue := response.Query1(nil, `//input[@name="SAMLResponse"]/@value`)
        data := url.Values{}
        data.Set("SAMLResponse", responsebodyvalue)
        u, _ = url.Parse(action)
        tp.resp, tp.responsebody, tp.err = tp.sendRequest(u, tp.resolv[u.Host], "POST", data.Encode(), tp.cookiejar)
    }
    // last POST doesn't actually get POSTed - we don't have a real SP ...
    return
}

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

func ExampleJustForKeepingLogImported() {
	log.Println("ExampleJustForKeepingLogImported")
}
