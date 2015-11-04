package wayffunctionaltest

import (
    "flag"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"testing"
)

type mod struct {
	path, value string
}

type mods []mod

type modsset map[string]mods

var (
	mdq = "https://phph.wayf.dk/MDQ/"

	defaulttp *Testparams

	avals = map[string][]string{
		"eduPersonPrincipalName": {"joe@this.is.not.a.valid.idp"},
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

	hub = flag.String("hub", "wayf.wayf.dk", "the hostname for the hub server to be tested")
	birk = flag.String("birk", "birk.wayf.dk", "the hostname for the BIRK server to be tested")
	trace = flag.Bool("xrace", false, "trace the request/response flow")
)

func TestMain(m *testing.M) {
	flag.Parse()
	log.Printf("hub: %s birk: %s\n", *hub, *birk)
	os.Exit(m.Run())
}

func Newtp() (tp *Testparams) {
	privatekeypw := os.Getenv("PW")
	if privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp = new(Testparams)
    tp.Spmd = gosaml.NewMD(mdq+"EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	tp.Hubspmd = gosaml.NewMD("https://wayf.wayf.dk/module.php/saml/sp/metadata.php/wayf.wayf.dk", "")
	tp.Hubidpmd = gosaml.NewMD("https://wayf.wayf.dk/saml2/idp/metadata.php", "")
	tp.Testidpmd = gosaml.NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	tp.Testidpviabirkmd = gosaml.NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")

	tp.Idpmd = tp.Testidpmd
	tp.Resolv = map[string]string{"wayf.wayf.dk": *hub, "birk.wayf.dk": *birk}
    tp.Logrequests = *trace

	tp.Attributestmt = b(avals)
	tp.Hashalgorithm = "sha1"

	keyname, _, certificate, err := tp.Idpmd.PublicKeyInfo("signing")
	if err != nil {
		log.Fatal(err)
	}

	tp.Certificate = certificate
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
	}
    defaulttp = nil
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

// ExampleAttributeNameFormat tests if the hub delivers the attributes in the correct format - only one (or none) is allowed
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
	for _, md := range sps {
        defaulttp = &Testparams{Spmd: md}
        tp := DoRunTestHub(nil)
		samlresponse := gosaml.Html2SAMLResponse(tp.Responsebody)
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

// ExamplePersistentNameID tests that the persistent nameID (and eptid) is the same from both the hub and BIRK
func ExamplePersistentNameID() {
	m := modsset{"requestmods": mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}}}
    n := modsset{"birkrequestmods": m["requestmods"]}
    hub := DoRunTestHub(m)
    birk := DoRunTestBirk(n)
    for _, tp := range []*Testparams{hub, birk} {
    	samlresponse := gosaml.Html2SAMLResponse(tp.Responsebody)
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/saml:AttributeValue")

		fmt.Printf("%s %s %s\n", nameidformat, nameid, eptid)
	}
	// Output:
    // urn:oasis:names:tc:SAML:2.0:nameid-format:persistent WAYF-DK-8b7b8966be6a12a8f70f760dda4e1522af2dba77 WAYF-DK-8b7b8966be6a12a8f70f760dda4e1522af2dba77
    // urn:oasis:names:tc:SAML:2.0:nameid-format:persistent WAYF-DK-8b7b8966be6a12a8f70f760dda4e1522af2dba77 WAYF-DK-8b7b8966be6a12a8f70f760dda4e1522af2dba77
}

// ExampleFullAttributeset1 test that the full attributeset is delivered to the default test sp
func ExampleFullAttributeset1() {
	hub := DoRunTestHub(nil)
	attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement")[0]
	fmt.Println(hub.Newresponse.Dump2(attributes))
	// Output:
    // <saml:AttributeStatement>
    //     <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">joe@example.com</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:other</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue>
    //       <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    //       <saml:AttributeValue xsi:type="xs:string">WAYF-DK-8b7b8966be6a12a8f70f760dda4e1522af2dba77</saml:AttributeValue>
    //     </saml:Attribute>
    //   </saml:AttributeStatement>
}

// ExampleFullAttributeset2 test that the full attributeset is delivered to the PHPH service
func ExampleFullAttributeset2() {
    defaulttp = &Testparams{Spmd: gosaml.NewMD(mdq+"HUB-OPS", "https://metadata.wayf.dk/PHPh")}
	hub := DoRunTestHub(nil)
	attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement")[0]
	fmt.Println(hub.Newresponse.Dump2(attributes))
	// Output:
    // <saml:AttributeStatement>
    //     <saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    //       <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    //       <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //   </saml:AttributeStatement>
}

// ExampleFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func ExampleFullEnctryptedAttributeset() {
    defaulttp = &Testparams{Encryptresponse: true, Spmd: gosaml.NewMD(mdq+"HUB-OPS", "https://metadata.wayf.dk/PHPh")}
	hub := DoRunTestHub(nil)
    if attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement"); attributes != nil {
	    fmt.Println(hub.Newresponse.Dump2(attributes[0]))
	}
	// Output:
    // <saml:AttributeStatement>
    //     <saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    //       <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //     <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    //       <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    //     </saml:Attribute>
    //   </saml:AttributeStatement>
}

// ExampleSignError1 tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func ExampleSignError1() {
	m := modsset{"responsemods": mods{mod{"//ds:SignatureValue", "+ 1234"}}}
	_ = DoRunTestHub(m)
	_ = DoRunTestBirk(m)

	// Output:
	// Unable to validate Signature
	// Error verifying signature on incoming SAMLResponse
}

// ExampleRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func ExampleRequestSchemaError() {
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse"}}}
	_ = DoRunTestHub(m)
	_ = DoRunTestBirk(m)
	// Output:
	// Invalid value of boolean attribute 'IsPassive': 'isfalse'
	// SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', attribute 'IsPassive': 'isfalse' is not a valid value of the atomic type 'xs:boolean'.
}

// ExampleNoEPPNError tests that the hub does not accept assertions with no eppn
func ExampleNoEPPNError() {
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]`, ""}}}
	_ = DoRunTestHub(m)
	// Output:
	// mandatory: eduPersonPrincipalName
}

// ExampleEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func ExampleEPPNScopingError() {
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe@example.com"}}}
	_ = DoRunTestHub(m)
	// Output:
}

// ExampleNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func ExampleNoLocalpartInEPPNError() {
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "@this.is.not.a.valid.idp"}}}
	_ = DoRunTestHub(m)
	// Output:
}

// ExampleNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func ExampleNoDomainInEPPNError() {
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe"}}}
	_ = DoRunTestHub(m)
	// Output:
}
