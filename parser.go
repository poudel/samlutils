package samlutils

import (
	"github.com/beevik/etree"
)

type SamlMetadata struct {
	EntityId    string
	Certificate string
	LoginUrl    string
	LogoutUrl   string
	RedirectUrl string
}

// ParseIdpMetadata This function tries to parse a string as SAML metadata file
// and returns the parsed content.
func ParseIdpMetadata(content string) SamlMetadata {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(content); err != nil {
		return SamlMetadata{}
	}
	return SamlMetadata{
		EntityId:    findEntityID(doc),
		Certificate: findCertificate(doc),
		LoginUrl:    findLoginUrl(doc),
		LogoutUrl:   findLogoutUrl(doc),
		RedirectUrl: findRedirectUrl(doc),
	}
}

func (s SamlMetadata) IsValid() bool {
	if s.LoginUrl != "" && s.EntityId != "" && s.Certificate != "" {
		return true
	}
	return false
}

func findEntityID(d *etree.Document) string {
	// This should also find namespaced entity descriptor i.e. md:EntityDescriptor
	entityDesc := d.FindElement("//EntityDescriptor")
	if entityDesc != nil {
		return entityDesc.SelectAttrValue("entityID", "")
	}
	return ""
}

func findLoginUrl(d *etree.Document) string {
	ssoService := d.FindElement("//SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']")
	if ssoService != nil {
		return ssoService.SelectAttrValue("Location", "")
	}
	return ""
}

func findLogoutUrl(d *etree.Document) string {
	ssoService := d.FindElement("//SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']")
	if ssoService != nil {
		return ssoService.SelectAttrValue("Location", "")
	}
	return ""
}

func findRedirectUrl(d *etree.Document) string {
	ssoService := d.FindElement("//SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']")
	if ssoService != nil {
		return ssoService.SelectAttrValue("Location", "")
	}
	return ""
}

func findCertificate(d *etree.Document) string {
	key := d.FindElement("//X509Certificate")
	if key != nil {
		return key.Text()
	}
	return ""
}
