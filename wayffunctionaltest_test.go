package wayffunctionaltest

import (
    "bytes"
    "flag"
	"fmt"
	"github.com/wayf-dk/gosaml"
    "io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"testing"
	"text/template"
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
	hubbe = flag.String("hubbe", "", "the hub backend server")
	birk = flag.String("birk", "birk.wayf.dk", "the hostname for the BIRK server to be tested")
	birkbe = flag.String("birkbe", "", "the birk backend server")
	trace = flag.Bool("xrace", false, "trace the request/response flow")
	nobirk = flag.Bool("nobirk", false, "test BIRK")
	env = flag.String("env", "dev", "which environment to test - if not dev")
	testcertpath = flag.String("testcertpath", "/etc/ssl/wayf/certs/wildcard.test.lan.pem", "path to the testing cert")

	old, r, w *os.File
    outC = make(chan string)
    templatevalues = map[string]map[string]string {
        "prod" : {
            "eptid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
            "pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
        },
        "dev" : {
            "eptid": "WAYF-DK-1d5bebf8f3cccb47e912cf0574af7484e97a2992",
            "pnameid": "WAYF-DK-1d5bebf8f3cccb47e912cf0574af7484e97a2992",
        },
        "beta" : {
            "eptid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
            "pnameid": "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2",
        },
    }
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
	os.Exit(m.Run())
}

func Newtp() (tp *Testparams) {
	privatekeypw := os.Getenv("PW")
	if privatekeypw == "" {
		log.Fatal("no PW environment var")
	}
	tp = new(Testparams)
	tp.Env = *env
	tp.Birk = !*nobirk && tp.Env != "beta"
    tp.Spmd = gosaml.NewMD(mdq+"HUB-OPS", "https://wayfsp.wayf.dk")
	tp.Hubspmd = gosaml.NewMD("https://wayf.wayf.dk/module.php/saml/sp/metadata.php/wayf.wayf.dk", "")
	tp.Hubidpmd = gosaml.NewMD("https://wayf.wayf.dk/saml2/idp/metadata.php", "")

	wayfserver := "wayf.wayf.dk"

    if tp.Env == "beta" {
	    wayfserver = "betawayf.wayf.dk"
        tp.Hubspmd = gosaml.NewMD("https://betawayf.wayf.dk/module.php/saml/sp/metadata.php/betawayf.wayf.dk", "")
        tp.Hubidpmd = gosaml.NewMD("https://betawayf.wayf.dk/saml2/idp/metadata.php", "")
    }

	tp.Resolv = map[string]string{wayfserver: *hub, "birk.wayf.dk": *birk}
	tp.Testidpmd = gosaml.NewMD(mdq+"HUB-OPS", "https://this.is.not.a.valid.idp")
	tp.Testidpviabirkmd = gosaml.NewMD(mdq+"BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")

	tp.Idpmd = tp.Testidpmd
    tp.Logrequests = *trace

	tp.Cookiejar = make(map[string]map[string]*http.Cookie)
	tp.Cookiejar["wayf.wayf.dk"] = make(map[string]*http.Cookie)
    tp.Cookiejar["wayf.wayf.dk"]["wayfid"] = &http.Cookie{Name: "wayfid", Value: *hubbe}
	tp.Cookiejar["birk.wayf.dk"] = make(map[string]*http.Cookie)
    tp.Cookiejar["birk.wayf.dk"]["birkid"] = &http.Cookie{Name: "birkid", Value: *birkbe}

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
        if defaulttp.Privatekey != "" {
            tp.Privatekey = defaulttp.Privatekey
        }
        if defaulttp.Privatekeypw != "" {
            tp.Privatekeypw = defaulttp.Privatekeypw
        }
	}
    defaulttp = nil
    tp.ViaKrib = false
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

// TestAttributeNameFormat tests if the hub delivers the attributes in the correct format - only one (or none) is allowed
// Currently if none is specified we deliver both but lie about the format so we say that it is basic even though it actually is uri
// As PHPH always uses uri we just count the number of RequestedAttributes
func TestAttributeNameFormat(t *testing.T) {
	const (
		mdcounturi   = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		mdcountbasic = "count(//md:RequestedAttribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
		mdcount  = "count(//md:RequestedAttribute)"
		ascounturi   = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri'])"
		ascountbasic = "count(//saml:Attribute[@NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'])"
	)
    stdoutstart()
	spmd := gosaml.NewMD("https://phph.wayf.dk/raw?type=feed&fed=wayf-fed", "")
	uri := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:uri' and wayf:redirect.validate='']/../..")
	urimd := gosaml.NewXpFromNode(uri[0])
	basic := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic' and wayf:redirect.validate='']/../..")
	basicmd := gosaml.NewXpFromNode(basic[0])
	both := spmd.Query(nil, "//wayf:wayf[wayf:AttributeNameFormat='' and wayf:redirect.validate='']/../..")
 	bothmd := gosaml.NewXpFromNode(both[0])

	sps := []*gosaml.Xp{urimd, basicmd, bothmd}
	for _, md := range sps {
        defaulttp = &Testparams{Spmd: md}
        tp := DoRunTestHub(nil)
		samlresponse := Html2SAMLResponse(tp)
		requested := md.QueryNumber(nil, mdcount)
		uricount := samlresponse.QueryNumber(nil, ascounturi)
		basiccount := samlresponse.QueryNumber(nil, ascountbasic)
		fmt.Printf("%t %t %t\n", basiccount == requested * 2, uricount == requested, basiccount == requested)
	}
	expected := `false true false
false false true
true false false
`
	stdoutend(t, expected)
}

// TestPersistentNameID tests that the persistent nameID (and eptid) is the same from both the hub and BIRK
func TestPersistentNameID(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}}}
	// BIRK always sends NameIDPolicy/@Format=transient - but respects what the hub sends back - thus we need to fix the request BIRK sends to the hub (WAYFMMISC-940)
    //n := modsset{"requestmods": m["requestmods"], "birkrequestmods": m["requestmods"]}
    hub := DoRunTestHub(m)
    birk := DoRunTestBirk(m)
    expected := ""
    for _, tp := range []*Testparams{hub, birk} {
        if tp == nil { continue; }
    	samlresponse := Html2SAMLResponse(tp)
		nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
		nameid := samlresponse.Query1(nil, "//saml:NameID")
		audience := samlresponse.Query1(nil, "//saml:Audience")
		spnamequalifier := samlresponse.Query1(nil, "//saml:NameID/@SPNameQualifier")
		eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/saml:AttributeValue")
		fmt.Printf("%s %s %s %s %s\n", nameidformat, nameid, eptid, audience, spnamequalifier)
		expected += `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent {{.pnameid}} {{.eptid}} https://wayfsp.wayf.dk https://wayfsp.wayf.dk
`
	}
    stdoutend(t, expected)
}

// TestTransientNameID tests that the transient nameID (and eptid) is the same from both the hub and BIRK
func TestTransientNameID(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}}}
	// BIRK always sends NameIDPolicy/@Format=transient - but respects what the hub sends back - thus we need to fix the request BIRK sends to the hub (WAYFMMISC-940)
    n := modsset{"birkrequestmods": m["requestmods"]}
    hub := DoRunTestHub(m)
    birk := DoRunTestBirk(n)
    expected := ""
    for _, tp := range []*Testparams{hub, birk} {
        if tp == nil { continue }
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

// TestUnspecifiedNameID tests that the
func TestUnspecifiedNameID(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"}}}
	// BIRK always sends NameIDPolicy/@Format=transient - but respects what the hub sends back - thus we need to fix the request BIRK sends to the hub (WAYFMMISC-940)
    n := modsset{"birkrequestmods": m["requestmods"]}
    hub := DoRunTestHub(m)
    birk := DoRunTestBirk(n)
    expected := ""
    for _, tp := range []*Testparams{hub, birk} {
        if tp == nil { continue }
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

// TestFullAttributeset1 test that the full attributeset is delivered to the default test sp
func TestFullAttributeset(t *testing.T) {
    stdoutstart()
	hub := DoRunTestHub(nil)
	if hub.Newresponse != nil {
	    attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement")[0]
	    fmt.Println(hub.Newresponse.Dump2(attributes))
	}
    expected := `<saml:AttributeStatement>
    <saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton &lt;SamlRequest id="abc"&gt;abc&lt;/SamlRequest&gt;</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Orphanage - home for the homeless</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="schacHomeOrganization" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="schacHomeOrganizationType" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:other</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="eduPersonTargetedID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">{{.eptid}}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton &lt;SamlRequest id="abc"&gt;abc&lt;/SamlRequest&gt;</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:2.5.4.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">Orphanage - home for the homeless</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">2</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:other</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">{{.eptid}}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
`
    stdoutend(t, expected)
}

func xTestFullAttributesetKrib(t *testing.T) {
    stdoutstart()
	hub := DoRunTestKrib(nil)
	attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement")[0]
	fmt.Println(hub.Newresponse.Dump2(attributes))
    expected := `<saml:AttributeStatement>
    <saml:Attribute Name="urn:oid:2.5.4.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">joe@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">urn:mace:terena.org:schac:homeOrganizationType:int:other</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue>
      <saml:AttributeValue xsi:type="xs:string">member</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">Anton Banton Cantonsen</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
      <saml:AttributeValue xsi:type="xs:string">{{.eptid}}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
`
    stdoutend(t, expected)
}

// TestFullAttributesetSP2 test that the full attributeset is delivered to the PHPH service
func TestFullAttributesetSP2(t *testing.T) {
    stdoutstart()
    defaulttp = &Testparams{Spmd: gosaml.NewMD(mdq+"HUB-OPS", "https://metadata.wayf.dk/PHPh")}
	hub := DoRunTestHub(nil)
	attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement")[0]
	fmt.Println(hub.Newresponse.Dump2(attributes))
    expected := `<saml:AttributeStatement>
    <saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
`
    stdoutend(t, expected)
}

// TestFullAttributeset3 test that the full attributeset is delivered to the default test sp - the assertion is encrypted
func TestFullEnctryptedAttributeset(t *testing.T) {
    stdoutstart()
    defaulttp = &Testparams{Encryptresponse: true, Spmd: gosaml.NewMD(mdq+"HUB-OPS", "https://metadata.wayf.dk/PHPh")}
	hub := DoRunTestHub(nil)
    if attributes := hub.Newresponse.Query(nil, "//saml:AttributeStatement"); attributes != nil {
	    fmt.Println(hub.Newresponse.Dump2(attributes[0]))
	}
    expected := `<saml:AttributeStatement>
    <saml:Attribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <saml:AttributeValue xsi:type="xs:string">joe@this.is.not.a.valid.idp</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
`
    stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedContent(t *testing.T) {
    stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion/saml:Issuer", "+ 1234"}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)

    expected := `Reference validation failed
`
    if birk != nil {
        expected += `Error verifying signature on incoming SAMLResponse
`
    }
    stdoutend(t, expected)
}

// TestSignErrorModifiedContent tests if the hub and BIRK reacts on errors in the signing of responses and assertions
func TestSignErrorModifiedSignature(t *testing.T) {
    stdoutstart()
	m := modsset{"responsemods": mods{mod{"//saml:Assertion//ds:SignatureValue", "+ 1234"}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)

    expected := `Unable to validate Signature
`
    if birk != nil {
        expected += `Error verifying signature on incoming SAMLResponse
`
    }
    stdoutend(t, expected)
}

// TestNoSignatureError tests if the hub and BIRK reacts assertions that are not signed
func TestNoSignatureError(t *testing.T) {
    stdoutstart()
	m := modsset{"responsemods": mods{mod{"//ds:Signature", ""}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)

    expected := `Neither the assertion nor the response was signed.
`
    if birk != nil { expected += `Error verifying signature on incoming SAMLResponse
`
    }
    stdoutend(t, expected)
}

// TestUnknownKeySignatureError tests if the hub and BIRK reacts on signing with an unknown key
func TestUnknownKeySignatureError(t *testing.T) {
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
	_ = DoRunTestHub(nil)
// need to do resign before sending to birk - not able to do that pt
//	_ = DoRunTestBirk(nil)

    expected := `Unable to validate Signature
`
    stdoutend(t, expected)
}

// TestRequestSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestRequestSchemaError(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@IsPassive", "isfalse"}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)
    expected := `Invalid value of boolean attribute 'IsPassive': 'isfalse'
`
    if birk != nil {
        expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', attribute 'IsPassive': 'isfalse' is not a valid value of the atomic type 'xs:boolean'.
`
    }
    stdoutend(t, expected)
}

// TestResponseSchemaError tests that the HUB and BIRK reacts on schema errors in requests
func TestResponseSchemaError(t *testing.T) {
    stdoutstart()
	m := modsset{"responsemods": mods{mod{"./@IssueInstant", "isfalse"}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)
    expected := `Invalid SAML2 timestamp passed to parseSAML2Time: isfalse
`
    if birk != nil {
        expected += `SAMLMessage does not validate according to schema: , error(s): line: 2:0, error: Element '{urn:oasis:names:tc:SAML:2.0:protocol}Response', attribute 'IssueInstant': 'isfalse' is not a valid value of the atomic type 'xs:dateTime'.
`
    }
    stdoutend(t, expected)
}

// TestNoEPPNError tests that the hub does not accept assertions with no eppn
func TestNoEPPNError(t *testing.T) {
    stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]`, ""}}}
	_ = DoRunTestHub(m)
    expected := `mandatory: eduPersonPrincipalName
`
    stdoutend(t, expected)
}

// TestEPPNScopingError tests that the hub does not accept scoping errors in eppn - currently it does
func TestEPPNScopingError(t *testing.T) {
    stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe@example.com"}}}
	_ = DoRunTestHub(m)
    expected := ``
    stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no localpart - currently it does
func TestNoLocalpartInEPPNError(t *testing.T) {
    stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "@this.is.not.a.valid.idp"}}}
	_ = DoRunTestHub(m)
    expected := ``
    stdoutend(t, expected)
}

// TestNoLocalpartInEPPNError tests that the hub does not accept eppn with no domain - currently it does
func TestNoDomainInEPPNError(t *testing.T) {
    stdoutstart()
	m := modsset{"attributemods": mods{mod{`/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, "joe"}}}
	_ = DoRunTestHub(m)
    expected := ``
    stdoutend(t, expected)
}

func TestUnknownSPError(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"./saml:Issuer", "https://www.example.com/unknownentity"}}}
	_ = DoRunTestHub(m)
	birk := DoRunTestBirk(m)
    expected := `Metadata not found for entity: https://www.example.com/unknownentity
`
    if birk != nil {
        expected += `Metadata for entity: https://www.example.com/unknownentity not found
`
    }
    stdoutend(t, expected)
}

// Use the line below for new birkservers
// Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
func TestUnknownIDPError(t *testing.T) {
    stdoutstart()
	m := modsset{"requestmods": mods{mod{"./@Destination", "https://birk.wayf.dk/birk.php/www.example.com/unknownentity"}}}
	expected := ""
	birk := DoRunTestBirk(m)
	if birk != nil {
        expected += `Metadata for entity: https://birk.wayf.dk/birk.php/www.example.com/unknownentity not found
`
    }
    stdoutend(t, expected)
}
