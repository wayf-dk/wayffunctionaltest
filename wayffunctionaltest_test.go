package wayffunctionaltest

/**
  test: -hub -birk -hybrid
*/

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lMDQ"
	. "github.com/y0ssar1an/q"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"text/template"
	"time"
)

type (
	mod struct {
		path, value string
		function    func(*goxml.Xp)
	}

	mods []mod

	modsset map[string]mods
	M       map[string]interface{} // just an alias
)

const (
	lMDQ_METADATA_SCHEMA_PATH = "src/github.com/wayf-dk/goxml/schemas/ws-federation.xsd"

	Wayfrequestedattributes = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.wayf.dk">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AttributeConsumingService index="0">
      <md:RequestedAttribute FriendlyName="sn" singular="true" must="true" Name="urn:oid:2.5.4.4" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="gn" singular="true" must="true" Name="urn:oid:2.5.4.42" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="cn" singular="true" must="true" Name="urn:oid:2.5.4.3" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" singular="true" mandatory="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="organizationName" singular="true" must="true" Name="urn:oid:2.5.4.10" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" singular="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" isRequired="true" />
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" isRequired="true" />
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" isRequired="true" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" isRequired="true" />
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" computed="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" isRequired="true" />
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" isRequired="true" />
	  <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" isRequired="true" />
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" isRequired="true" />
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`
)

var (
	mdqsources = map[string]map[string]*lMDQ.MDQ{
		"prodz": {
			"internal":        &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_INTERNAL"},
			"externalIdP":     &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "HYBRID_EXTERNAL_IDP"},
			"externalSP":      &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_EXTERNAL_SP"},
			"wayf_hub_public": &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "WAYF_HUB_PUBLIC"},
		},
		"prod": {
			"internal":        &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_INTERNAL"},
			"externalIdP":     &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_EXTERNAL_IDP"},
			"externalSP":      &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_EXTERNAL_SP"},
			"wayf_hub_public": &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "WAYF_HUB_PUBLIC"},
		},
		"dev": {
			"internal":        &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_INTERNAL"},
			"externalIdP":     &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "HYBRID_EXTERNAL_IDP"},
			"externalSP":      &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_EXTERNAL_SP"},
			"wayf_hub_public": &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "WAYF_HUB_PUBLIC"},
		},
		"hybrid": {
			"internal":        &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_INTERNAL"},
			"externalIdP":     &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "HYBRID_EXTERNAL_IDP"},
			"externalSP":      &lMDQ.MDQ{Path: "../hybrid-metadata.mddb", Table: "HYBRID_EXTERNAL_SP"},
			"wayf_hub_public": &lMDQ.MDQ{Path: "../hybrid-metadata-test.mddb", Table: "WAYF_HUB_PUBLIC"},
		},
	}

	wayf_hub_public, wayf2_hub_public, internal, externalIdP, externalSP *lMDQ.MDQ

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
	krib             = flag.String("krib", "krib.wayf.dk", "the krib.wayf.dk server")
	trace            = flag.Bool("xtrace", false, "trace the request/response flow")
	logxml           = flag.Bool("logxml", false, "dump requests/responses in xml")
	dohub            = flag.Bool("dohub", false, "do test the hub")
	dobirk           = flag.Bool("dobirk", false, "do test BIRK")
	dobirk2          = flag.Bool("dobirk2", false, "do test BIRK")
	dokrib           = flag.Bool("dokrib", false, "do (only) test KRIB - implies !birk and !hub")
	env              = flag.String("env", "dev", "which environment to test dev, hybrid, prod - if not dev")
	refreshmd        = flag.Bool("refreshmd", true, "update local metadatcache before testing")
	testcertpath     = flag.String("testcertpath", "/etc/ssl/wayf/certs/wildcard.test.lan.pem", "path to the testing cert")
	wayfAttCSDoc     = goxml.NewXpFromString(Wayfrequestedattributes)
	wayfAttCSElement = wayfAttCSDoc.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	testSPs *goxml.Xp

	old, r, w      *os.File
	outC           = make(chan string)
	templatevalues = map[string]map[string]string{
		"prod": {
			"eptid":   "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
			"pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
		},
		"dev": {
			"eptid":   "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
			"pnameid": "WAYF-DK-a7379f69e957371dc49350a27b704093c0b813f1",
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

func TestMain(m *testing.M) {
	flag.Parse()
	log.Printf("hub: %q backend: %q birk: %q backend: %q\n", *hub, *hubbe, *birk, *birkbe)
	mdsources := map[string]**lMDQ.MDQ{
		"wayf_hub_public": &wayf_hub_public,
		"internal":        &internal,
		"externalIdP":     &externalIdP,
		"externalSP":      &externalSP,
	}
	var err error
	for i, md := range mdsources {
		*md = mdqsources[*env][i]
		err = (*md).Open()
		if err != nil {
			log.Fatalln(err)
		}
	}
	// need non-birk, non-request.validate and non-IDPList SPs for testing ....
	// look for them in the test_internal feed as wayf:wayf attributes are not yet int the prod feed
	var numberOfTestSPs int
	testSPs, numberOfTestSPs, _ = internal.MDQFilter("/*[not(contains(@entityID, 'birk.wayf.dk/birk.php'))]/*/wayf:wayf[not(wayf:IDPList!='') and wayf:redirect.validate='']/../../md:SPSSODescriptor/..")
	//	testSPs, numberOfTestSPs, _ = internal.MDQFilter("/*[not(contains(@entityID, 'birk.wayf.dk/birk.php'))]/*/wayf:wayf[not(wayf:IDPList!='')]/../../md:SPSSODescriptor/..")
	if numberOfTestSPs == 0 {
		log.Fatal("No testSP candidates")
	}
	os.Exit(m.Run())
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
}

func Newtp(overwrite *Testparams) (tp *Testparams) {
	tp = new(Testparams)
	tp.Privatekeypw = os.Getenv("PW")
	if tp.Privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	var err error
	tp.Env = *env
	tp.Krib = *dokrib
	tp.Birk = *dobirk
	tp.Hub = *dohub
	tp.Spmd, _ = internal.MDQ("https://wayfsp.wayf.dk")
	tp.Hubspmd, err = wayf_hub_public.MDQ("https://wayf.wayf.dk")

	//	tp.Hubspmd.QueryDashP(nil, "/md:SPSSODescriptor/md:AssertionConsumerService[1]/@Location", "https://wayf.wayf.dk/saml2/sp/AssertionConsumerService.php", nil)
	//	log.Println(tp.Hubspmd.Pp())

	tp.Hubspmd.Query(nil, "./md:SPSSODescriptor")[0].AddChild(wayfAttCSDoc.CopyNode(wayfAttCSElement, 1))
	tp.Hubidpmd, _ = wayf_hub_public.MDQ("https://wayf.wayf.dk")

	wayfserver := "wayf.wayf.dk"
	/*
		if tp.Env == "beta" {
			wayfserver = "betawayf.wayf.dk"
			tp.Hubspmd = newMD("https://betawayf.wayf.dk/module.php/saml/sp/metadata.php/betawayf.wayf.dk")
			tp.Hubidpmd = newMD("https://betawayf.wayf.dk/saml2/idp/metadata.php")
		}
	*/
	tp.Resolv = map[string]string{wayfserver: *hub, "birk.wayf.dk": *birk, "krib.wayf.dk": *krib, "ds.wayf.dk": "localhost"}
	tp.Idpmd, _ = internal.MDQ("https://this.is.not.a.valid.idp")
	tp.Firstidpmd = tp.Hubidpmd
	if tp.Birk {
		tp.Birkmd, _ = externalIdP.MDQ("https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
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

	keyname, _, err := gosaml.PublicKeyInfo(certs[0].NodeValue())
	if err != nil {
		log.Fatal(err)
	}

	tp.Certificate = certs[0].NodeValue()
	pk, err := ioutil.ReadFile("/etc/ssl/wayf/signing/" + keyname + ".key")
	if err != nil {
		log.Fatal(err)
	}
	tp.Privatekey = string(pk)
	if overwrite != nil {
		if overwrite.Hubspmd != nil {
			tp.Hubspmd = overwrite.Hubspmd
		}
		if overwrite.Hubidpmd != nil {
			tp.Hubidpmd = overwrite.Hubidpmd
			tp.Firstidpmd = tp.Hubidpmd
		}
		if overwrite.Encryptresponse {
			tp.Encryptresponse = true
		}
		if overwrite.Spmd != nil {
			tp.Spmd = overwrite.Spmd
		}
		if overwrite.Privatekey != "" {
			tp.Privatekey = overwrite.Privatekey
		}
		if overwrite.Privatekeypw != "" {
			tp.Privatekeypw = overwrite.Privatekeypw
		}
	}

	//	m := mapFields(tp)
	//    log.Println("Mapped fields: ", m)
	return
}

func mapFields(x *Testparams) M {
	o := make(M)
	v := reflect.ValueOf(x).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := t.FieldByIndex([]int{i})
		o[f.Name] = v.FieldByIndex([]int{i}).Interface()
	}
	return o
}

func b(attrs map[string][]string) (ats *goxml.Xp) {
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
	attrnameformats := []string{"uri", "basic", "both"}
	attrnameformatqueries := map[string]string{
		"uri":   "/*/*/*/wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri']/../../@entityID",
		"basic": "/*/*/*/wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic']/../../@entityID",
		"both":  "/*/*/*/wayf:wayf[wayf:AttributeNameFormat='']/../../@entityID",
	}

	dorun := func(f testrun) {
		for _, attrname := range attrnameformats {
			eID := testSPs.Query1(nil, attrnameformatqueries[attrname])
			md, _ := internal.MDQ(eID)
			if md == nil {
				log.Fatalln("No SP found for testing attributenameformat: ", attrname)
			}
			tp := f(nil, &Testparams{Spmd: md})
			if tp != nil {
				//samlresponse := Html2SAMLResponse(tp)
				requested := md.QueryNumber(nil, mdcount)
				uricount := tp.Newresponse.QueryNumber(nil, ascounturi)
				basiccount := tp.Newresponse.QueryNumber(nil, ascountbasic)
				fmt.Printf("%t %t %t\n", basiccount == requested*2, uricount == requested, basiccount == requested)
				//fmt.Printf("requested %d uri %d basic %d\n", requested, uricount, basiccount)
			}
		}
	}
	expected := ""
	dorun(DoRunTestHub)
	dorun(DoRunTestBirk)
	dorun(DoRunTestKrib)
	if *dohub {
		expected += `false true false
false false true
false false true
`
	}
	if *dokrib || *dobirk {
		expected += `false true false
false false true
false false true
`
	}
	stdoutend(t, expected)
}

// TestMultipleSPs tests just test a lot of SPs - if any fails signature validation it fails
func xTestMultipleSPs(t *testing.T) {
	//stdoutstart()

	spquery := "/*/*/@entityID"

	dorun := func(f testrun) {
		eIDs := testSPs.Query(nil, spquery)

		for _, eID := range eIDs {
			md, _ := internal.MDQ(eID.NodeValue())
			if md == nil {
				log.Fatalln("No SP found for testing multiple SPs: ", eID)
			}
			f(nil, &Testparams{Spmd: md})
		}
	}
	dorun(DoRunTestHub)
	//expected := ""
	//stdoutend(t, expected)
}

// TestConsentDisabled tests that a SP with consent.disabled set actually bypasses the consent form
func TestConsentDisabled(t *testing.T) {
	stdoutstart()
	// We need to get at the wayf:wayf elements - thus we got directly to the feed !!!
	//	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	expected := ""
	// find an entity with consent disabled, but no a birk entity as we know that using ssp does not understand the wayf namespace yet ...
	entityID := testSPs.Query1(nil, "/*/*/*/wayf:wayf[wayf:consent.disable='1']/../../md:SPSSODescriptor/../@entityID")
	if entityID != "" {
		entitymd, _ := internal.MDQ(entityID)

		dorun := func(f testrun) {
			tp := f(nil, &Testparams{Spmd: entitymd})
			if tp != nil {
				fmt.Printf("consent given %t\n", tp.ConsentGiven)
			}
		}
		if *dohub {
			dorun(DoRunTestHub)
			expected += `consent given false
`
		}
		if *dobirk {
			dorun(DoRunTestBirk)
			expected += `consent given false
`
		}
	} else {
		expected += "no entity suited for test found"
	}
	stdoutend(t, expected)
}

// TestPersistentNameID tests that the persistent nameID (and eptid) is the same from both the hub and BIRK
func xTestPersistentNameID(t *testing.T) {
	stdoutstart()
	// We need to get at the wayf:wayf elements - thus we got directly to the feed !!!
	//	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	expected := ""
	entityID := testSPs.Query1(nil, "/*/*/md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']/../md:AttributeConsumingService/md:RequestedAttribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10' or @Name='eduPersonTargetedID']/../../../@entityID")
	entitymd, _ := internal.MDQ(entityID)
	if entitymd == nil {
		log.Fatalln("no SP found for testing TestPersistentNameID")
	}

	dorun := func(f testrun) {
		tp := f(nil, &Testparams{Spmd: entitymd})
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
	//	spmd := newMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed")
	expected := ""
	eID := testSPs.Query1(nil, "/*/*/md:SPSSODescriptor/md:NameIDFormat[.='urn:oasis:names:tc:SAML:2.0:nameid-format:transient']/../../@entityID")
	entitymd, _ := internal.MDQ(eID)
	var tp *Testparams
	entityID := ""
	dorun := func(f testrun) {
		tp = f(nil, &Testparams{Spmd: entitymd})
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
		reg := regexp.MustCompile("^(https?)://(.*)")
		birkEntityID := reg.ReplaceAllString(entityID, "${1}://birk.wayf.dk/birk.php/${2}-proxy")
		if !reg.MatchString(birkEntityID) { // urn format
			birkEntityID = "urn:oid:1.3.6.1.4.1.39153:42:" + birkEntityID
		}
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
	// common res for hub and birk
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
`
	res := DoRunTestBirk(nil, nil)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}

	res = DoRunTestHub(nil, nil)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	res = DoRunTestKrib(nil, nil)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
	}
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestFullAttributesetSP2(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internal.MDQ("https://metadata.wayf.dk/PHPh")
	overwrite := &Testparams{Spmd: spmd}
	hub := DoRunTestHub(nil, overwrite)
	if hub != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, hub.Newresponse)
	}
	birk := DoRunTestBirk(nil, overwrite)
	if birk != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, birk.Newresponse)
	}
	krib := DoRunTestKrib(nil, overwrite)
	if krib != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, krib.Newresponse)
	}
	expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
/*
func TestFullAttributesetSP3(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internal.MDQ("https://metadata.wayf.dk/PHPh")
	hub2idpmd, _ := wayf2_hub_public.MDQ("https://wayf.wayf.dk")
	overwrite := &Testparams{Spmd: spmd, Hubidpmd: hub2idpmd}
	hub := DoRunTestHub(nil, overwrite)
	if hub != nil {
		hub.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	birk := DoRunTestBirk(nil, overwrite)
	if birk != nil {
		birk.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	krib := DoRunTestKrib(nil, overwrite)
	if krib != nil {
		krib.Newresponse.AttributeCanonicalDump()
		expected += `urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}
*/

// TestFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func TestFullEncryptedAttributeset1(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internal.MDQ("https://metadata.wayf.dk/PHPh")
	overwrite := &Testparams{Encryptresponse: true, Spmd: spmd}
	res := DoRunTestHub(nil, overwrite)
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	res = DoRunTestKrib(nil, overwrite)
	if res == nil {
		res = DoRunTestBirk(nil, overwrite)
	}
	if res != nil {
		gosaml.AttributeCanonicalDump(os.Stdout, res.Newresponse)
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}

/*
func TestFullEncryptedAttributeset2(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internal.MDQ("https://metadata.wayf.dk/PHPh")
	hub2spmd, _ := wayf2_hub_public.MDQ("https://wayf.wayf.dk")
	overwrite := &Testparams{Encryptresponse: true, Spmd: spmd, Hubspmd: hub2spmd}

	res := DoRunTestHub(nil, overwrite)
	if res != nil {
		res.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	res = DoRunTestKrib(nil, overwrite)
	if res == nil {
		res = DoRunTestBirk(nil, overwrite)
	}
	if res != nil {
		res.Newresponse.AttributeCanonicalDump()
		expected += `eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}
*/

// TestFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func TestAccessForNonIntersectingAdHocFederations(t *testing.T) {
	var expected string
	stdoutstart()
	spmd, _ := internal.MDQ("https://this.is.not.a.valid.sp")
	overwrite := &Testparams{Spmd: spmd}
	res := DoRunTestHub(nil, overwrite)
	if res != nil {
		expected += `unknown error
`
	}
	res = DoRunTestBirk(nil, overwrite)
	if res != nil {
		expected += `unknown error
`
	}
	res = DoRunTestKrib(nil, overwrite)
	if res != nil {
		expected += `no common federations
`
	}
	stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedContent(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion/saml:Issuer", "+ 1234", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Reference validation failed
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `unable to validate signature: digest mismatch
`
	}
	stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedSignature(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion//ds:SignatureValue", "+ 1234", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Unable to validate Signature
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `unable to validate signature: crypto/rsa: verification error
`
	}
	stdoutend(t, expected)
}

// TestNoSignatureError tests if the hub and BIRK reacts assertions that are not signed
func TestNoSignatureError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"//ds:Signature", "", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Neither the assertion nor the response was signed.
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `Error verifying signature on incoming SAMLResponse
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `No signatures found
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

	// need to do resign before sending to birk - not able to do that pt
	//	_ = DoRunTestBirk(nil)
	if DoRunTestHub(nil, &Testparams{Privatekey: pk, Privatekeypw: "-"}) != nil {
		expected += `Unable to validate Signature
`
	}
	if DoRunTestKrib(nil, &Testparams{Privatekey: pk, Privatekeypw: "-"}) != nil {
		expected += `unable to validate signature: crypto/rsa: verification error
`
	}
	stdoutend(t, expected)
}

// TestRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestRequestSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Invalid value of boolean attribute 'IsPassive': 'isfalse'
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', attribute 'IsPassive': 'isfalse' is not a valid value of the atomic type 'xs:boolean'.
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `["cause:schema validation failed"]
`
	}
	stdoutend(t, expected)
}

// TestResponseSchemaError tests that the HUB and BIRK reacts on schema errors in responses
func TestResponseSchemaError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"./@IssueInstant", "isfalse", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Invalid SAML2 timestamp passed to parseSAML2Time: isfalse
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}Response', attribute 'IssueInstant': 'isfalse' is not a valid value of the atomic type 'xs:dateTime'.
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `["cause:schema validation failed"]
`
	}
	stdoutend(t, expected)
}

// TestNoEPPNError tests that the hub does not accept assertions with no eppn
func TestNoEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`//saml:Attribute[@Name="eduPersonPrincipalName"]`, "", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `mandatory: eduPersonPrincipalName
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `eppn does not seem to be an eppn:
`
	}
	stdoutend(t, expected)
}

// TestEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func TestEPPNScopingError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe@example.com", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `security domain 'example.com' for eppn does not match any scopes
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `security domain 'example.com' for eppn does not match any scopes
`
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func TestNoLocalpartInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "@this.is.not.a.valid.idp", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += ``
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `eppn does not seem to be an eppn: @this.is.not.a.valid.idp
`
	}
	stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func TestNoDomainInEPPNError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += ``
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `eppn does not seem to be an eppn: joe
`
	}
	stdoutend(t, expected)
}

// TestUnknownSPError test how the birk and the hub reacts on requests from an unknown sP
func TestUnknownSPError(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"requestmods": mods{mod{"./saml:Issuer", "https://www.example.com/unknownentity", nil}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Metadata not found for entity: https://www.example.com/unknownentity
`
	}
	if DoRunTestBirk(m, nil) != nil {
		expected += `Metadata for entity: https://www.example.com/unknownentity not found
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `["cause:sql: no rows in result set","err:Metadata not found","key:https://www.example.com/unknownentity","table:HYBRID_INTERNAL"]
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
	m := modsset{"requestmods": mods{mod{"./@Destination", "https://birk.wayf.dk/birk.php/www.example.com/unknownentity", nil}}}
	if DoRunTestBirk(m, nil) != nil {
		expected += `Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `["cause:sql: no rows in result set","err:Metadata not found","key:https://birk.wayf.dk/birk.php/www.example.com/unknownentity","table:HYBRID_EXTERNAL_IDP"]
`
	}
	stdoutend(t, expected)
}

func xTestXSW1(t *testing.T) {
	var expected string
	stdoutstart()
	m := modsset{"responsemods": mods{mod{"", "", ApplyXSW1}}}
	if DoRunTestHub(m, nil) != nil {
		expected += `Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
`
	}
	if DoRunTestKrib(m, nil) != nil {
		expected += `["cause:sql: no rows in result set","err:Metadata not found","key:https://birk.wayf.dk/birk.php/www.example.com/unknownentity","table:HYBRID_EXTERNAL_IDP"]

`
	}
	stdoutend(t, expected)
}

// from https://github.com/SAMLRaider/SAMLRaider/blob/master/src/main/java/helpers/XSWHelpers.java
func ApplyXSW1(xp *goxml.Xp) {
	log.Println(xp.Doc.Dump(true))
	response := xp.Query(nil, "/samlp:Response[1]/saml:Assertion[1]")[0]
	clonedResponse := xp.CopyNode(response, 1)
	log.Println(clonedResponse.ToString(0, false))
	clonedSignature := xp.Query(clonedResponse, "././.")[0]
	log.Println(clonedSignature.ToString(1, false))
	parent, _ := clonedSignature.(types.Element).ParentNode()
	parent.RemoveChild(clonedSignature)

	signature := xp.Query(response, "ds:Signature[1]")[0]
	signature.AddChild(clonedResponse)
	response.(types.Element).SetAttribute("ID", "_evil_response_ID")
	log.Println(xp.Doc.Dump(true))
}

func xTestSpeed(t *testing.T) {
	const gorutines = 50
	const iterations = 50
	spmd, _ := internal.MDQ("https://metadata.wayf.dk/PHPh")
	for i := 0; i < gorutines; i++ {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < iterations; j++ {
				starttime := time.Now()
				DoRunTestHub(nil, &Testparams{Spmd: spmd})
				log.Println(i, j, time.Since(starttime).Seconds())
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}
