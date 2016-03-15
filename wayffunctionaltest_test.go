package wayffunctionaltest

/**
  test: -hub -birk -hybrid


*/

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/wayf-dk/gohybrid"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/lMDQ"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"text/template"
)

type (
	mod struct {
		path, value string
	}

	mods []mod

	modsset map[string]mods
)

var (
	//mdq = "https://phph.wayf.dk/MDQ/"
	mdq = "https://test-phph.test.lan/MDQ/"

	mdqsources = map[string]map[string]string{
		"prod": {
			"wayf-hub-public": "/home/mz/prod_hub.mddb",
			"HUB-OPS":         "/home/mz/prod_hub_ops.mddb",
			"BIRK-OPS":        "/home/mz/prod_birk.mddb",
		},
		"hybrid": {
			"wayf-hub-public": "/home/mz/test_hub.mddb",
			"HUB-OPS":         "/home/mz/test_hub_ops.mddb",
			"BIRK-OPS":        "/home/mz/test_edugain.mddb",
		},
	}

	wayf_hub_public, hub_ops, birk_ops *lMDQ.MDQ

	defaulttp *Testparams

	avals = map[string][]string{
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

	hub              = flag.String("hub", "wayf.wayf.dk", "the hostname for the hub server to be tested")
	hubbe            = flag.String("hubbe", "", "the hub backend server")
	birk             = flag.String("birk", "birk.wayf.dk", "the hostname for the BIRK server to be tested")
	birkbe           = flag.String("birkbe", "", "the birk backend server")
	trace            = flag.Bool("xrace", false, "trace the request/response flow")
	logxml           = flag.Bool("logxml", false, "dump requests/responses in xml")
	dohub            = flag.Bool("dohub", false, "do test the hub")
	dobirk           = flag.Bool("dobirk", false, "do test BIRK")
	dokrib           = flag.Bool("dokrib", false, "do (only) test KRIB - implies !birk and !hub")
	env              = flag.String("env", "dev", "which environment to test dev, hybrid, prod - if not dev")
	testcertpath     = flag.String("testcertpath", "/etc/ssl/wayf/certs/wildcard.test.lan.pem", "path to the testing cert")
	wayfAttCSDoc     = gosaml.NewXp(main.Wayfrequestedattributes)
	wayfAttCSElement = wayfAttCSDoc.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	old, r, w      *os.File
	outC           = make(chan string)
	templatevalues = map[string]map[string]string{
		"prod": {
			"eptid":   "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
		},
		"dev": {
			"eptid":   "WAYF-DK-1d5bebf8f3cccb47e912cf0574af7484e97a2992",
			"pnameid": "WAYF-DK-1d5bebf8f3cccb47e912cf0574af7484e97a2992",
		},
		"hybrid": {
			"eptid":   "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
			"pnameid": "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
		},
		"beta": {
			"eptid":   "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
		},
	}

	wg sync.WaitGroup
)

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
	if expected != got {
		t.Errorf("\nexpected:\n%s\ngot:\n%s\n", expected, got)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.Printf("hub: %q backend: %q birk: %q backend: %q\n", *hub, *hubbe, *birk, *birkbe)
	wayf_hub_public, _ = lMDQ.Open(mdqsources[*env]["wayf-hub-public"])
	hub_ops, _ = lMDQ.Open(mdqsources[*env]["HUB-OPS"])
	birk_ops, _ = lMDQ.Open(mdqsources[*env]["BIRK-OPS"])
	os.Exit(m.Run())
}

func newMD(mdq string) (mdxp *gosaml.Xp) {
	// full EntitiesDescriptor xml
	md, err := lMDQ.Get(mdq)
	if err != nil {
		log.Fatalf("could not get: %s, error: %s", mdq, err)
	}
	mdxp = gosaml.NewXp(md)
	return
}

func Newtp() (tp *Testparams) {
	privatekeypw := os.Getenv("PW")
	if privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp = new(Testparams)
	tp.Env = *env
	tp.Krib = *dokrib
	tp.Birk = *dobirk
	tp.Hub = *dohub
	tp.Spmd, _ = hub_ops.MDQ("https://wayfsp.wayf.dk")
	tp.Hubspmd, _ = wayf_hub_public.MDQ("https://wayf.wayf.dk")
	tp.Hubspmd.Query(nil, "./md:SPSSODescriptor")[0].AddChild(wayfAttCSDoc.CopyNode(wayfAttCSElement, 1))
	tp.Hubidpmd, _ = wayf_hub_public.MDQ("https://wayf.wayf.dk")

	wayfserver := "wayf.wayf.dk"

	if tp.Env == "beta" {
		wayfserver = "betawayf.wayf.dk"
		tp.Hubspmd = newMD("https://betawayf.wayf.dk/module.php/saml/sp/metadata.php/betawayf.wayf.dk")
		tp.Hubidpmd = newMD("https://betawayf.wayf.dk/saml2/idp/metadata.php")
	}

	tp.Resolv = map[string]string{wayfserver: *hub, "birk.wayf.dk": *birk}
	tp.Idpmd, _ = hub_ops.MDQ("https://this.is.not.a.valid.idp")
	tp.Firstidpmd = tp.Hubidpmd
	if tp.Birk {
		tp.Birkmd, _ = birk_ops.MDQ("https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
	}

	tp.DSIdpentityID = "https://this.is.not.a.valid.idp"
	if tp.Krib {
		tp.DSIdpentityID = "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp"
	}
	tp.Trace = *trace
	tp.Logxml = *logxml

	tp.Cookiejar = make(map[string]map[string]*http.Cookie)
	tp.Cookiejar["wayf.wayf.dk"] = make(map[string]*http.Cookie)
	tp.Cookiejar["wayf.wayf.dk"]["wayfid"] = &http.Cookie{Name: "wayfid", Value: *hubbe}
	tp.Cookiejar["birk.wayf.dk"] = make(map[string]*http.Cookie)
	tp.Cookiejar["birk.wayf.dk"]["birkid"] = &http.Cookie{Name: "birkid", Value: *birkbe}

	tp.Attributestmt = b(avals)
	tp.Hashalgorithm = "sha1"

	certs := tp.Idpmd.Query(nil, `//md:KeyDescriptor[@use="signing" or not(@use)]/ds:KeyInfo/ds:X509Data/ds:X509Certificate`)
	if len(certs) == 0 {
		fmt.Errorf("Could not find signing cert for: %s", tp.Idpmd.Query1(nil, "/@entityID"))
	}

	keyname, _, err := gosaml.PublicKeyInfo(tp.Idpmd.NodeGetContent(certs[0]))
	if err != nil {
		log.Fatal(err)
	}

	tp.Certificate = tp.Idpmd.NodeGetContent(certs[0])
	pk, err := ioutil.ReadFile("/etc/ssl/wayf/signing/" + keyname + ".key")
	if err != nil {
		log.Fatal(err)
	}
	tp.Privatekey = string(pk)
	tp.Privatekeypw = os.Getenv("PW")
	if defaulttp != nil {
		if defaulttp.Encryptresponse {
			tp.Encryptresponse = true
		}
		if defaulttp.Spmd != nil {
			tp.Spmd = defaulttp.Spmd
		}
		if defaulttp.Privatekey != "" {
			tp.Privatekey = defaulttp.Privatekey
		}
		if defaulttp.Privatekeypw != "" {
			tp.Privatekeypw = defaulttp.Privatekeypw
		}
	}
	defaulttp = nil
	return
}

func b(attrs map[string][]string) (ats *gosaml.Xp) {
	template := []byte(`<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema"/>`)
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
	// We need to get at the wayf:wayf elements - thus we got directly to the feed !!!
	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	uri := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri' and wayf:redirect.validate='']/../..")
	urimd := gosaml.NewXpFromNode(uri[0])
	basic := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic' and wayf:redirect.validate='']/../..")
	basicmd := gosaml.NewXpFromNode(basic[0])
	both := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='' and wayf:redirect.validate='']/../..")
	bothmd := gosaml.NewXpFromNode(both[0])

	dorun := func(f testrun) {
		sps := []*gosaml.Xp{urimd, basicmd, bothmd}
		for _, md := range sps {
			defaulttp = &Testparams{Spmd: md}
			tp := f(nil)
			if tp != nil {
				//samlresponse := Html2SAMLResponse(tp)
				requested := md.QueryNumber(nil, mdcount)
				uricount := tp.Newresponse.QueryNumber(nil, ascounturi)
				basiccount := tp.Newresponse.QueryNumber(nil, ascountbasic)
				fmt.Printf("%t %t %t\n", basiccount == requested*2, uricount == requested, basiccount == requested)
			}
		}
	}
	expected := ""
	dorun(DoRunTestHub)
	dorun(DoRunTestBirk)
	if *dohub || *dobirk {
		expected += `false true false
false false true
true false false
`
	}
	if *dokrib {
		expected += `false true false
false false true
false false false
`
	}
	stdoutend(t, expected)
}

// TestPersistentNameID tests that the persistent nameID (and eptid) is the same from both the hub and BIRK
func TestPersistentNameID(t *testing.T) {
	stdoutstart()
	// We need to get at the wayf:wayf elements - thus we got directly to the feed !!!
	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	expected := ""
	entities := spmd.Query(nil, "//wayf:wayf[wayf:redirect.validate='']/../../md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']/../..")
	entitymd := gosaml.NewXpFromNode(entities[0])

	dorun := func(f testrun) {
		defaulttp = &Testparams{Spmd: entitymd}
		tp := f(nil)
		if tp != nil {
			samlresponse := Html2SAMLResponse(tp)
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
	dorun(DoRunTestHub)
	dorun(DoRunTestBirk)
	stdoutend(t, expected)
}

// TestTransientNameID tests that the transient nameID (and eptid) is the same from both the hub and BIRK
func TestTransientNameID(t *testing.T) {
	stdoutstart()
	// We need to get at the wayf:wayf elements - thus we got directly to the feed !!!
	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	expected := ""
	entities := spmd.Query(nil, "//wayf:wayf[wayf:redirect.validate='']/../../md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:transient']/../..")
	entitymd := gosaml.NewXpFromNode(entities[0])
	var tp *Testparams
	entityID := ""
	dorun := func(f testrun) {
		defaulttp = &Testparams{Spmd: entitymd}
		tp = f(nil)
		if tp != nil {
			samlresponse := Html2SAMLResponse(tp)
			entityID = entitymd.Query1(nil, "@entityID")
			nameid := samlresponse.Query1(nil, "//saml:NameID")
			nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
			audience := samlresponse.Query1(nil, "//saml:Audience")
			spnamequalifier := samlresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
			fmt.Printf("%s %t %s %s\n", nameidformat, nameid != "", audience, spnamequalifier)
		}
	}
	dorun(DoRunTestHub)
	if tp != nil {
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:transient true ` + entityID + ` ` + entityID + "\n"
	}
	dorun(DoRunTestBirk)
	if tp != nil {
		birkEntityID := regexp.MustCompile("https?://(.*)").ReplaceAllString(entityID, "https://birk.wayf.dk/birk.php/${1}-proxy")
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:transient true ` + entityID + ` ` + birkEntityID + "\n"
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

// TestFullAttributeset1 test that the full attributeset is delivered to the default test sp
func TestFullAttributeset(t *testing.T) {
	var expected string
	stdoutstart()
	hub := DoRunTestHub(nil)
	if hub == nil {
		hub = DoRunTestBirk(nil)
	}
	if hub != nil {
		hub.Newresponse.AttributeCanonicalDump()
		expected += `cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    2
eduPersonEntitlement urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    https://example.com/course101
eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    student
eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonScopedAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    member@this.is.not.a.valid.idp
    student@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    {{.eptid}}
gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton <SamlRequest id="abc">abc</SamlRequest>
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
urn:oid:0.9.2342.19200300.100.1.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
urn:oid:1.3.6.1.4.1.2428.90.1.4 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    123456789
urn:oid:1.3.6.1.4.1.25178.1.0.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    1858
urn:oid:1.3.6.1.4.1.25178.1.2.10 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    urn:mace:terena.org:schac:homeOrganizationType:int:other
urn:oid:1.3.6.1.4.1.25178.1.2.15 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234
urn:oid:1.3.6.1.4.1.25178.1.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    18580824
urn:oid:1.3.6.1.4.1.25178.1.2.5 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    dk
urn:oid:1.3.6.1.4.1.25178.1.2.9 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.10 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2
urn:oid:1.3.6.1.4.1.5923.1.1.1.11 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    2
urn:oid:1.3.6.1.4.1.5923.1.1.1.5 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    student
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.7 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    https://example.com/course101
urn:oid:1.3.6.1.4.1.5923.1.1.1.9 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    member@this.is.not.a.valid.idp
    student@this.is.not.a.valid.idp
urn:oid:2.16.840.1.113730.3.1.39 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    da
urn:oid:2.5.4.10 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Orphanage - home for the homeless
urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
urn:oid:2.5.4.4 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Cantonsen
urn:oid:2.5.4.42 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton <SamlRequest id="abc">abc</SamlRequest>
`
	}
	krib := DoRunTestKrib(nil)
	if krib != nil {
		krib.Newresponse.AttributeCanonicalDump()
		expected += `cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    2
eduPersonEntitlement urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    https://example.com/course101
eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    student
eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonScopedAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    member@this.is.not.a.valid.idp
    student@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1
gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton <SamlRequest id="abc">abc</SamlRequest>
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
	}
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestFullAttributesetSP2(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := hub_ops.MDQ("https://metadata.wayf.dk/PHPh")
	defaulttp = &Testparams{Spmd: spmd}
	hub := DoRunTestHub(nil)
	if hub != nil {
		hub.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	defaulttp = &Testparams{Spmd: spmd}
	birk := DoRunTestBirk(nil)
	if birk != nil {
		birk.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	defaulttp = &Testparams{Spmd: spmd}
	krib := DoRunTestKrib(nil)
	if krib != nil {
		krib.Newresponse.AttributeCanonicalDump()
		expected += `urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}

// TestFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func TestFullEnctryptedAttributeset(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := hub_ops.MDQ("https://metadata.wayf.dk/PHPh")
	defaulttp = &Testparams{Encryptresponse: true, Spmd: spmd}
	hub := DoRunTestHub(nil)
	if hub == nil {
		defaulttp = &Testparams{Encryptresponse: true, Spmd: spmd}
		hub = DoRunTestBirk(nil)
	}
	if hub != nil {
		hub.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	defaulttp = &Testparams{Encryptresponse: true, Spmd: spmd}
	krib := DoRunTestKrib(nil)
	if krib != nil {
		krib.Newresponse.AttributeCanonicalDump()
		expected += `urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedContent(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion/saml:Issuer", "+ 1234"}}}
	if DoRunTestHub(m) != nil {
		expected += `Reference validation failed
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
	}
	stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedSignature(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion//ds:SignatureValue", "+ 1234"}}}
	if DoRunTestHub(m) != nil {
		expected += `Unable to validate Signature
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
	}
	stdoutend(t, expected)
}

// TestNoSignatureError tests if the hub and BIRK reacts assertions that are not signed
func TestNoSignatureError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//ds:Signature", ""}}}
	if DoRunTestHub(m) != nil {
		expected += `Neither the assertion nor the response was signed.
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
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

	defaulttp = &Testparams{Privatekey: pk, Privatekeypw: "-"}
	// need to do resign before sending to birk - not able to do that pt
	//	_ = DoRunTestBirk(nil)
	if DoRunTestHub(nil) != nil {
		expected += `Unable to validate Signature
`
	}
	stdoutend(t, expected)
}

// TestRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestRequestSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse"}}}
	if DoRunTestHub(m) != nil {
		expected += `Invalid value of boolean attribute 'IsPassive': 'isfalse'
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', attribute 'IsPassive': 'isfalse' is not a valid value of the atomic type 'xs:boolean'.
`
	}
	stdoutend(t, expected)
}

// TestResponseSchemaError tests that the HUB and BIRK reacts on schema errors in responses
func TestResponseSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./@IssueInstant", "isfalse"}}}
	if DoRunTestHub(m) != nil {
		expected += `Invalid SAML2 timestamp passed to parseSAML2Time: isfalse
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}Response', attribute 'IssueInstant': 'isfalse' is not a valid value of the atomic type 'xs:dateTime'.
`
	}
	stdoutend(t, expected)
}

// TestNoEPPNError tests that the hub does not accept assertions with no eppn
func TestNoEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, ""}}}
	if DoRunTestHub(m) != nil {
		expected += `mandatory: eduPersonPrincipalName
`
	}
	stdoutend(t, expected)
}

// TestEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func TestEPPNScopingError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/./././saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe@example.com"}}}
	if DoRunTestHub(m) != nil {
		expected += ``
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func TestNoLocalpartInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/./././saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "@this.is.not.a.valid.idp"}}}
	if DoRunTestHub(m) != nil {
		expected += ``
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func TestNoDomainInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/./././saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe"}}}
	if DoRunTestHub(m) != nil {
		expected += ``
	}
	stdoutend(t, expected)
}

// TestUnknownSPError test how the birk and the hub reacts on requests from an unknown sP
func TestUnknownSPError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./saml:Issuer", "https://www.example.com/unknownentity"}}}
	if DoRunTestHub(m) != nil {
		expected += `Metadata not found for entity: https://www.example.com/unknownentity
`
	}
	if DoRunTestBirk(m) != nil {
		expected += `Metadata for entity: https://www.example.com/unknownentity not found
`
	}
	stdoutend(t, expected)
}

// TestUnknownIDPError tests how BIRK reacts on requests to an unknown IdP
// Use the line below for new birkservers
// Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
func TestUnknownIDPError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@Destination", "https://birk.wayf.dk/birk.php/www.example.com/unknownentity"}}}
	if DoRunTestBirk(m) != nil {
		expected += `Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
`
	}
	stdoutend(t, expected)
}

// TestFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func xTestSpeed(t *testing.T) {
	const gorutines = 10
	const iterations = 10
	//spmd, _ := hub_ops.MDQ("https://metadata.wayf.dk/PHPh")
	//defaulttp = &Testparams{Spmd: spmd}
	for i := 0; i < gorutines; i++ {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < iterations; j++ {
				DoRunTestHub(nil)
				log.Println(i, j)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}
