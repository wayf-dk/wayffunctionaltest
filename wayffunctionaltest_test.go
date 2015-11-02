package wayffunctionaltest

// https://wiki.wayf.dk/display/WAYKI/Design+for+WAYF+functional+tests

import (
	"fmt"
	"github.com/wayf-dk/gosaml"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

type mod struct {
	path, value string
}
type mods []mod

var (
	mdq = "https://phph.wayf.dk/MDQ/"
	_   = log.Printf // For debugging; delete when done.

	wg sync.WaitGroup

	basic2iod = map[string]string{
		`cn`:                          `urn:oid:2.5.4.3`,
		`displayName`:                 `urn:oid:2.16.840.1.113730.3.1.241`,
		`eduPersonAffiliation`:        `urn:oid:1.3.6.1.4.1.5923.1.1.1.1`,
		`eduPersonAssurance`:          `urn:oid:1.3.6.1.4.1.5923.1.1.1.11`,
		`eduPersonEntitlement`:        `urn:oid:1.3.6.1.4.1.5923.1.1.1.7`,
		`eduPersonPrimaryAffiliation`: `urn:oid:1.3.6.1.4.1.5923.1.1.1.5`,
		`eduPersonPrincipalName`:      `urn:oid:1.3.6.1.4.1.5923.1.1.1.6`,
		`eduPersonScopedAffiliation`:  `urn:oid:1.3.6.1.4.1.5923.1.1.1.9`,
		`eduPersonTargetedID`:         `urn:oid:1.3.6.1.4.1.5923.1.1.1.10`,
		`gn`:                        `urn:oid:2.5.4.42`,
		`mail`:                      `urn:oid:0.9.2342.19200300.100.1.3`,
		`norEduPersonLIN`:           `urn:oid:1.3.6.1.4.1.2428.90.1.4`,
		`organizationName`:          `urn:oid:2.5.4.10`,
		`preferredLanguage`:         `urn:oid:2.16.840.1.113730.3.1.39`,
		`schacCountryOfCitizenship`: `urn:oid:1.3.6.1.4.1.25178.1.2.5`,
		`schacDateOfBirth`:          `urn:oid:1.3.6.1.4.1.25178.1.2.3`,
		`schacHomeOrganization`:     `urn:oid:1.3.6.1.4.1.25178.1.2.9`,
		`schacHomeOrganizationType`: `urn:oid:1.3.6.1.4.1.25178.1.2.10`,
		`schacPersonalUniqueID`:     `urn:oid:1.3.6.1.4.1.25178.1.2.15`,
		`schacYearOfBirth`:          `urn:oid:1.3.6.1.4.1.25178.1.0.2.3`,
		`sn`:                        `urn:oid:2.5.4.4`,
	}

	avals = map[string][]string{
		"eduPersonPrincipalName": {"joe@orphanage.wayf.dk"},
		"mail":                       {"joe@example.com"},
		"gn":                         {`Anton Banton <SamlRequest id="abc">abc</SamlRequest>`},
		"sn":                         {"Cantonsen"},
		"norEduPersonLIN":            {"123456789"},
		"eduPersonScopedAffiliation": {"student@abc.orphanage.wayf.dk", "member@abc.orphanage.wayf.dk"},
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
)

func Newtp() (tp *Testparams) {
	privatekeypw := os.Getenv("PW")
	if privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp = new(Testparams)
	tp.spmd = gosaml.NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	tp.hubspmd = gosaml.NewMD("https://wayf.wayf.dk/module.php/saml/sp/metadata.php/wayf.wayf.dk", "")
	tp.hubidpmd = gosaml.NewMD("https://wayf.wayf.dk/saml2/idp/metadata.php", "")
	tp.testidpmd = gosaml.NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	tp.testidpviabirkmd = gosaml.NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")

	tp.idpmd = tp.testidpmd
	tp.resolv = map[string]string{"wayf.wayf.dk": "wayf-02.wayf.dk:443", "birk.wayf.dk": "birk-03.wayf.dk:443"}
	tp.logrequests = true
	tp.attributestmt = b(avals)
	tp.hashalgorithm = "sha1"

	keyname, certificate, err := gosaml.KeyNameFromMD(tp.idpmd)
	if err != nil {
		log.Fatal(err)
	}

	tp.certificate = certificate
	pk, err := ioutil.ReadFile("/etc/ssl/wayf/signing/" + keyname + ".key")
	if err != nil {
		log.Fatal(err)
	}
	tp.privatekey = string(pk)
	tp.privatekeypw = os.Getenv("PW")
	return
}

func b(attrs map[string][]string) (ats *gosaml.Xp) {
	template := []byte(`<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>`)
	ats = gosaml.NewXp(template)
	i := 1
	for attr, attrvals := range attrs {
		attrelement := ats.QueryDashP(nil, `saml:Attribute[`+strconv.Itoa(i)+`]`, "", nil)
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

// ExampleError1 tests if the HUB delivers the attributes in the correct format - only one (or none) is allowed
// Currently if none is specified we deliver both but lie about the format so we say that it is basic even though it actually is uri
func ExampleAttributeNameFormat() {
	const (
		mdcounturi   = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		mdcountbasic = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
		mdcountboth  = "count(//md:RequestedAttribute[not(@NameFormat)])"
		ascounturi   = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		ascountbasic = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
	)

	spmd := gosaml.NewMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed", "")
	uri := spmd.Query1(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri' and wayf:redirect.validate='']/../../@entityID")
	urimd := gosaml.NewMD(mdq+"HUB-OPS", uri)
	basic := spmd.Query1(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic' and wayf:redirect.validate='']/../../@entityID")
	basicmd := gosaml.NewMD(mdq+"HUB-OPS", basic)
	both := spmd.Query1(nil, "//wayf:wayf[wayf:AttributeNameFormat='' and wayf:redirect.validate='']/../../@entityID")
	bothmd := gosaml.NewMD(mdq+"HUB-OPS", both)
	// We shall be able to extract a subtree from a EntitiesDescriptor to a new document

	sps := []*gosaml.Xp{urimd, basicmd, bothmd}
	tp := Newtp()
	for _, md := range sps {
		tp.spmd = md.CpXp()
		tp.SSOCreateInitialRequest()
		tp.SSOSendRequest()
		tp.SSOSendResponse()
		if tp.resp.StatusCode == 500 {
			response := gosaml.NewHtmlXp(tp.responsebody)
			fmt.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))
			log.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))
			continue
		}
		samlresponse := gosaml.Html2SAMLResponse(tp.responsebody)
		requesteduri := md.QueryNumber(nil, mdcounturi) > 0
		requestedbasic := md.QueryNumber(nil, mdcountbasic) > 0
		requestedboth := md.QueryNumber(nil, mdcountboth) > 0
		uricount := samlresponse.QueryNumber(nil, ascounturi) > 0
		basiccount := samlresponse.QueryNumber(nil, ascountbasic) > 0
		fmt.Printf("%t %t %t %t %t\n", requesteduri, requestedbasic, requestedboth, uricount, basiccount)
	}
	// Output:
	// true false false true false
	// false true false false true
	// false false true false true
}

// Tests if the persistent nameID is the same from both the hub and BIRK
func ExamplePersistantNameID() {
	tp := Newtp()

	metadata := []*gosaml.Xp{tp.testidpmd, tp.testidpviabirkmd}
	persistentmods := mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}}

	for _, md := range metadata {
		tp.idpmd = md.CpXp()
		tp.SSOCreateInitialRequest()
		for _, change := range persistentmods {
			tp.initialrequest.QueryDashP(nil, change.path, change.value, nil)
		}
		tp.SSOSendRequest1()
		// now after birk if used - fix the request from BIRK so it requests persistent nameidformat
		authnrequest := gosaml.Url2SAMLRequest(tp.resp.Location())
		for _, change := range persistentmods {
    		authnrequest.QueryDashP(nil, change.path, change.value, nil)
		}
		tp.resp.Header.Set("Location", gosaml.SAMLRequest2Url(authnrequest).String())

		tp.SSOSendRequest2()
		tp.SSOSendResponse()
		if tp.resp.StatusCode == 500 {
			response := gosaml.NewHtmlXp(tp.responsebody)
			fmt.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))
			continue
		}
		samlresponse := gosaml.Html2SAMLResponse(tp.responsebody)
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/saml:AttributeValue")

		fmt.Printf("%s %s %s\n", nameidformat, nameid, eptid)
	}
	// Output:
	// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent WAYF-DK-d63ec0a98508943252307a0b23df50e8780ec9c5 WAYF-DK-d63ec0a98508943252307a0b23df50e8780ec9c5
	// urn:oasis:names:tc:SAML:2.0:nameid-format:persistent WAYF-DK-d63ec0a98508943252307a0b23df50e8780ec9c5 WAYF-DK-d63ec0a98508943252307a0b23df50e8780ec9c5
}

// ExampleSignError1 tests if the HUB and BIRK reacts on errors in the signing of responses and assertions
func ExampleSignError1() {
	tp := Newtp()

	tp.idpmd = tp.testidpmd.CpXp()
	tp.SSOCreateInitialRequest()
	tp.SSOSendRequest()
	sig := tp.newresponse.Query(nil, "//ds:SignatureValue")[0]
	sigvalue := tp.newresponse.Query1(nil, "//ds:SignatureValue")
	tp.newresponse.NodeSetContent(sig, "x"+sigvalue)
	tp.SSOSendResponse1()

	response := gosaml.NewHtmlXp(tp.responsebody)
	fmt.Println(response.Query1(nil, `//a[@id="errormsg"]/text()`))

	tp.idpmd = tp.testidpviabirkmd
	tp.SSOCreateInitialRequest()
	tp.SSOSendRequest()
	tp.SSOSendResponse()
	tp.newresponse.QueryDashP(nil, "/samlp:Response/saml:Assertion/saml:Issuer", "anton", nil)
	tp.SSOSendResponse2()
	fmt.Println(strings.SplitN(string(tp.responsebody), " ", 2)[1])
	// Output:
	// Unable to validate Signature
	// Error verifying signature on incoming SAMLResponse
}

func xxExamplePerformance() {
	concurrent := 100
	for j := 0; j < concurrent; j++ {
		//go sign()
		wg.Add(1)
		go xExamplePerformance(j)
	}
	wg.Wait()
	// Output:
	// anton
}

func xExamplePerformance(j int) {
	requests := 10
	tp := Newtp()
	for i := 0; i < requests; i++ {
		tp.SSOCreateInitialRequest()
		tp.SSOSendRequest()
		tp.SSOSendResponse()
	}
	wg.Done()
}