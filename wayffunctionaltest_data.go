package wayffunctionaltest

var (
	testAttributes = map[string][]string{
		"cn":                          {"Anton Banton Cantonsen"},
		"displayName":                 {"Anton Banton Cantonsen"},
		"eduPersonAffiliation":        {"alum"},
		"eduPersonAssurance":          {"2"},
		"eduPersonEntitlement":        {"https://example.com/course101"},
		"eduPersonPrimaryAffiliation": {"student"},
		"eduPersonPrincipalName":      {"joe@this.is.not.a.valid.idp"},
		"eduPersonScopedAffiliation":  {"student@this.is.not.a.valid.idp", "member@this.is.not.a.valid.idp"},
		"entryUUID":                   {"entryUUID"},
		"gn":                          {`Anton Banton <SamlRequest id="abc">abc</SamlRequest>`},
		"mail":                        {"joe@example.com"},
		"norEduPersonLIN":             {"123456789"},
		"organizationName":            {"This Is Not A Valid IdP!"},
		"preferredLanguage":           {"da"},
		"schacCountryOfCitizenship":   {"dk"},
		"schacHomeOrganizationType":   {"abc"},
		"schacPersonalUniqueID":       {"urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234"},
		"sn":                          {"Cantonsen"},
	}

	jwt2SAMLPreflight = `{
  "AssertionConsumerServiceURL": [
    "https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
  ],
  "ForceAuthn": null,
  "IsPassive": null,
  "Issuer": [
    "https://wayf.wayf.dk"
  ],
  "RequesterID": [
    "https://wayfsp.wayf.dk"
  ],
  "commonfederations": [
    "true"
  ],
  "hub": [
    "true"
  ],
  "idpfeds": [
    "WAYF",
    "HUBIDP",
    "oes.dk"
  ],
  "protocol": [
    "AuthnRequest"
  ],
  "spfeds": [
    "WAYF"
  ]
} https://wayfsp.wayf.dk
`

    modstAttributes = `eduPersonAssurance https://modst.dk/sso/claims/assurancelevel https://modst.dk/sso/claims
    2
eduPersonPrincipalName http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name https://modst.dk/sso/claims
    joe@this.is.not.a.valid.idp
eduPersonPrincipalName https://modst.dk/sso/claims/userid https://modst.dk/sso/claims
    joe@this.is.not.a.valid.idp
entryUUID https://modst.dk/sso/claims/uniqueid https://modst.dk/sso/claims
    entryUUID
gn https://modst.dk/sso/claims/givenname https://modst.dk/sso/claims
    Anton Banton &lt;SamlRequest id=&#34;abc&#34;&gt;abc&lt;/SamlRequest&gt;
mail https://modst.dk/sso/claims/email https://modst.dk/sso/claims
    joe@example.com
modstlogonmethod https://modst.dk/sso/claims/logonmethod https://modst.dk/sso/claims
    username-password-protected-transport
oioCvrNumberIdentifier https://modst.dk/sso/claims/cvr https://modst.dk/sso/claims
    12345678
sn https://modst.dk/sso/claims/surname https://modst.dk/sso/claims
    Cantonsen
`

    fullAttributeSet = `cn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton Cantonsen
eduPersonAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    alum
    member
    student
eduPersonAssurance urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    2
eduPersonEntitlement urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    https://example.com/course101
eduPersonPrimaryAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    student
eduPersonPrincipalName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@this.is.not.a.valid.idp
eduPersonScopedAffiliation urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    alum@this.is.not.a.valid.idp
    member@this.is.not.a.valid.idp
    student@this.is.not.a.valid.idp
eduPersonTargetedID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    {{.eptid}}
entryUUID urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    entryUUID
gn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Anton Banton &lt;SamlRequest id=&#34;abc&#34;&gt;abc&lt;/SamlRequest&gt;
mail urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    joe@example.com
norEduPersonLIN urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    123456789
organizationName urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    This Is Not A Valid IdP!
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
sn NameStandIn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Cantonsen
sn urn:oasis:names:tc:SAML:2.0:attrname-format:basic
    Cantonsen
`
	fullAttributeSetJSON = `{
    "NameStandIn": [
        "Cantonsen"
    ],
    "aud": "https://wayfsp.wayf.dk",
    "cn": [
        "Anton Banton Cantonsen"
    ],
    "eduPersonAffiliation": [
        "alum",
        "student",
        "member"
    ],
    "eduPersonAssurance": [
        "2"
    ],
    "eduPersonEntitlement": [
        "https://example.com/course101"
    ],
    "eduPersonPrimaryAffiliation": [
        "student"
    ],
    "eduPersonPrincipalName": [
        "joe@this.is.not.a.valid.idp"
    ],
    "eduPersonScopedAffiliation": [
        "student@this.is.not.a.valid.idp",
        "member@this.is.not.a.valid.idp",
        "alum@this.is.not.a.valid.idp"
    ],
    "eduPersonTargetedID": [
        "WAYF-DK-c52a92a5467ae336a2be77cd06719c645e72dfd2"
    ],
    "entryUUID": [
        "entryUUID"
    ],
    "exp": "1234",
    "gn": [
        "Anton Banton \u003cSamlRequest id=\"abc\"\u003eabc\u003c/SamlRequest\u003e"
    ],
    "iat": "1234",
    "iss": "https://wayf.wayf.dk",
    "mail": [
        "joe@example.com"
    ],
    "nbf": "1234",
    "norEduPersonLIN": [
        "123456789"
    ],
    "organizationName": [
        "This Is Not A Valid IdP!"
    ],
    "preferredLanguage": [
        "da"
    ],
    "saml:AuthenticatingAuthority": [
        "https://this.is.not.a.valid.idp"
    ],
    "schacCountryOfCitizenship": [
        "dk"
    ],
    "schacDateOfBirth": [
        "18580824"
    ],
    "schacHomeOrganization": [
        "this.is.not.a.valid.idp"
    ],
    "schacHomeOrganizationType": [
        "urn:mace:terena.org:schac:homeOrganizationType:int:other"
    ],
    "schacPersonalUniqueID": [
        "urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408586234"
    ],
    "schacYearOfBirth": [
        "1858"
    ],
    "sn": [
        "Cantonsen"
    ]
}
`



)
