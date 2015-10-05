package wayffunctionaltest

import (
	"github.com/wayf-dk/gosaml"
	"log"
	"os"
	"testing"
)

type mod struct {
    path, value string
}
type mods []mod

var (
	mdq = "https://phph.wayf.dk/MDQ/"

	spmetadata, idpmetadata, hubmetadata, testidpmetadata, testidpviabirkmetadata *gosaml.Xp

    wayfmdxml = []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" entityID="https://wayf.wayf.dk">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
        <mdui:Description xml:lang="da">WAYF - den danske identitetsfederation for forskning og uddannelse</mdui:Description>
        <mdui:Description xml:lang="en">WAYF - The Danish identity federation for research and higher education</mdui:Description>
        <mdui:DisplayName xml:lang="da">WAYF - Where Are You From</mdui:DisplayName>
        <mdui:DisplayName xml:lang="en">WAYF - Where Are You From</mdui:DisplayName>
      </mdui:UIInfo>
      <shibmd:Scope regexp="false">adm.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aub.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">civil.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">create.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">es.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hst.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">id.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">its.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">learning.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">m-tech.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">plan.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sbi.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">staff.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">student.aau.dk@aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kb.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hi.is</shibmd:Scope>
      <shibmd:Scope regexp="false">ruc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">orphanage.wayf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucl.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aau.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">viauc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">drlund-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">iha.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sdu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">itu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aip.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">gg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">lg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">mg.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sosur.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sska.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sss.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">its.itsf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sikker-adgang.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ibc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">natmus.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">rungsted-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucsj.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sosuc.cphwest.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dab.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ism.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fbo.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fsv.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vfc.minibib.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dsl.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">zbc.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">frsgym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">cbs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">uniit.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dskd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ku.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kristne-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dsn.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vordingborg-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dmjx.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hasseris-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">apoteket.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">erhvervsakademiaarhus.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kadk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dtu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucn.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">frhavn-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sde.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eal.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">hrs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">sceu.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vgtgym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">odense.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">au.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">knord.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vibkat.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">vghf.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eucnord.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">phmetropol.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">handelsskolen.com</shibmd:Scope>
      <shibmd:Scope regexp="false">cphbusiness.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">kea.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eadania.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">dansidp.stads.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">umit.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">campusvejle.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">rosborg-gym.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fhavnhs.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ah.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">basyd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">statsbiblioteket.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">eamv.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">aams.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">regionsjaelland.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">fms.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">smk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">msk.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">drcmr.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">simac.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">ucsyd.dk</shibmd:Scope>
      <shibmd:Scope regexp="false">this.is.not.a.valid.idp</shibmd:Scope>
    </md:Extensions>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SingleLogoutService.php"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/saml2/idp/SSOService.php"/>
  </md:IDPSSODescriptor> <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
   <md:KeyDescriptor use="signing">
     <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
       <ds:X509Data>
         <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </md:KeyDescriptor>
   <md:KeyDescriptor use="encryption">
     <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
       <ds:X509Data>
         <ds:X509Certificate>MIIE3TCCA8WgAwIBAgISESFgDbqp6YXwPvILGKAnrUDtMA0GCSqGSIb3DQEBBQUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIERvbWFpbiBWYWxpZGF0aW9uIENBIC0gRzIwHhcNMTIwMTA0MDkzNTU0WhcNMTcwMTAzMDkzNTU0WjBHMQswCQYDVQQGEwJESzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRUwEwYDVQQDEwx3YXlmLndheWYuZGswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAosqmcujXhA49vHQLLTKZxFTz3guMRnwHvUxz5vvuMPYVTGl+fXPdq9ULhkNc1jlCr4+pFOwLdy9zkuAn8dK7grQEaU58K0uF4MTyKixFnPvU3806roL8PnrmUQ2t8y76U9jzsk/B3Ggi5pVqhOktHpZyzz1yBpE14R+/DPzHrpKIFJY4N2uzoBrcEAsJY6aTUfIaB/NEpe4BY8sDZ3CTuU3tWUfhdlZESYsmngdnHD6k0HUKti9F43UM6JyN6fz7T70JlHAcTHzYKhjtPLcWG8lWFqNtry7fCYC5SlKn4zmyifoASxRoH3EuxtE/Fmmt+M6I83kg3H0R1b8PHimfAgMBAAGjggGxMIIBrTAOBgNVHQ8BAf8EBAMCBaAwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAQowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wFwYDVR0RBBAwDoIMd2F5Zi53YXlmLmRrMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3MvZ3Nkb21haW52YWxnMi5jcmwwgYgGCCsGAQUFBwEBBHwwejBBBggrBgEFBQcwAoY1aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nkb21haW52YWxnMi5jcnQwNQYIKwYBBQUHMAGGKWh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9nc2RvbWFpbnZhbGcyMB0GA1UdDgQWBBS44PHFNUdj1NTiqkjShHfvW50SIzAfBgNVHSMEGDAWgBSWrfqwW7mDZCp2whyKadpC3P79KDANBgkqhkiG9w0BAQUFAAOCAQEAjqwtcRjT+gYKMhgwpJ4MNpL6W80efrcMDdWnZUJzN081ht0dcQqvdAVjkWylEQbbS1LXc9OZecRJGR1vxBzS7bq0lRauPuYodzOsDzP4cEW/W+PvWIEIpm5yIBZ31P7VnRpaRwmeff8OlhDOvM4+wdovRvIpLgyeyW05R2i4DenI8juCaWXNG+CATj35gW3uh/LD9DBzpZDoQ41/5yJPZUuiHfZtnW0M7oVnhidn5sT319Xiag3Jlqe7dx1D+b0oZVDTbwrECOdROTcbOkbGsr4VleBcTtL5RoF4cDokYB6LpIDmSMiBV6DztPcrPC/ERS/tEBMbfMWVAus4f0SvdQ==</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </md:KeyDescriptor>
   <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk"/>
   <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk" index="0"/>
   <md:AttributeConsumingService index="0">
     <md:ServiceName xml:lang="en">WAYF - Where are you from</md:ServiceName>
     <md:ServiceName xml:lang="da">WAYF - Where are you from</md:ServiceName>
     <md:ServiceDescription xml:lang="en">Denmarks Identity Federation for Education and Research.</md:ServiceDescription>
     <md:ServiceDescription xml:lang="da">Danmarks Identitetsfoederation for Uddannelse og Forskning.</md:ServiceDescription>
     <md:RequestedAttribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="gn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="cn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonPrimaryAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="organizationName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="eduPersonAssurance" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" isRequired="true"/>
     <md:RequestedAttribute Name="schacPersonalUniqueID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="schacCountryOfCitizenship" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="eduPersonScopedAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="preferredLanguage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="eduPersonEntitlement" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
     <md:RequestedAttribute Name="norEduPersonLIN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
   </md:AttributeConsumingService>
 </md:SPSSODescriptor>
 <md:Organization>
   <md:OrganizationName xml:lang="en">WAYF</md:OrganizationName>
   <md:OrganizationName xml:lang="da">WAYF</md:OrganizationName>
   <md:OrganizationDisplayName xml:lang="en">WAYF - Where are you from</md:OrganizationDisplayName>
   <md:OrganizationDisplayName xml:lang="da">WAYF - Where are you from</md:OrganizationDisplayName>
   <md:OrganizationURL xml:lang="da">http://wayf.dk/index.php/da</md:OrganizationURL>
   <md:OrganizationURL xml:lang="en">http://wayf.dk/index.php/en</md:OrganizationURL>
 </md:Organization>
 <md:ContactPerson contactType="technical">
   <md:GivenName>WAYF</md:GivenName>
   <md:SurName>Operations</md:SurName>
   <md:EmailAddress>drift@wayf.dk</md:EmailAddress>
 </md:ContactPerson>
</md:EntityDescriptor>`)
)

func TestMain(m *testing.M) {
	spmetadata = gosaml.NewMD(mdq, "EDUGAIN", "https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	idpmetadata = gosaml.NewMD(mdq, "EDUGAIN", "https://aai-logon.switch.ch/idp/shibboleth")
	//wayfmetadata = NewMD(mdq, "wayf-hub-public", "https://wayf.wayf.dk")
	hubmetadata = gosaml.NewXp(wayfmdxml)
	testidpmetadata = gosaml.NewMD(mdq, "HUB-OPS", "https://this.is.not.a.valid.idp")
	testidpviabirkmetadata = gosaml.NewMD(mdq, "BIRK-OPS", "https://birk.wayf.dk/birk.php/this.is.not.a.valid.idp")
	os.Exit(m.Run())
}

func ExampleError2() {
    tp := new(Testparams)
    tp.spmd = spmetadata.CpXp()
    tp.testidpmd = testidpmetadata.CpXp()
    tp.hubmd = hubmetadata.CpXp()
    tp.resolv = map[string]string{"wayf.wayf.dk": "wayf-03.wayf.dk:443"}
    metadata := []*gosaml.Xp{testidpmetadata, testidpviabirkmetadata}
    persistentmods := mods{mod{"/samlp:AuthnRequest/samlp:NameIDPolicy[1]/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}}

    for _, md := range metadata {
        tp.idpmd = md.CpXp()
        tp.SSOCreateInitialRequest()
        for _, change := range persistentmods {
            tp.initialrequest.QueryDashP(nil, change.path, change.value, nil)
        }
        tp.SSOSendRequest()
        tp.SSOSendResponse()
        samlresponse := gosaml.Html2SAMLResponse(tp.responsebody)
        nameidformat := samlresponse.Query1(nil, "//saml:NameID/@Format")
        nameid := samlresponse.Query1(nil, "//saml:NameID")
        eptid := samlresponse.Query1(nil, "//saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.10']/saml:AttributeValue")

        log.Printf("via HUB:  %s %s %s\n", nameidformat, nameid, eptid)
        //log.Printf("%s\n", samlresponse.Pp())
    }
	// Output:
	// anton
}
