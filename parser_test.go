package samlutils

import "testing"

func assertMetadataAttrs(t *testing.T, metadata string, expectedEntityId string, expectedCert string, expectedLoginUrl string, expectedRedirectUrl string, expectedLogoutUrl string) {
	output := ParseIdpMetadata(metadata)

	if output.EntityId != expectedEntityId {
		t.Fatalf("entityID Expected: %s, Got: %s", expectedEntityId, output.EntityId)
	}

	if output.Certificate != expectedCert {
		t.Fatalf("Cert Expected: %s, Got: %s", expectedCert, output.Certificate)
	}

	if output.LoginUrl != expectedLoginUrl {
		t.Fatalf("LoginUrl Expected: %s, Got: %s", expectedLoginUrl, output.LoginUrl)
	}

	if output.RedirectUrl != expectedRedirectUrl {
		t.Fatalf("RedirectUrl Expected: %s, Got: %s", expectedRedirectUrl, output.RedirectUrl)
	}

	if output.LogoutUrl != expectedLogoutUrl {
		t.Fatalf("LogoutUrl Expected: %s, Got: %s", expectedLogoutUrl, output.LogoutUrl)
	}

}

func TestParseIdpMetadataOktaExample(t *testing.T) {
	assertMetadataAttrs(
		t,
		EXAMPLE_OKTA_METADATA,
		"http://www.okta.com/exkexl6xc9MhzqiC30h7",
		`MIIDpDCCAoygAwIBAgIGAWMnhv7cMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
         A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
         MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi03NzEyMDIxHDAaBgkqhkiG9w0BCQEW
         DWluZm9Ab2t0YS5jb20wHhcNMTgwNTAzMTk0MTI4WhcNMjgwNTAzMTk0MjI4WjCBkjELMAkGA1UE
         BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
         BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNzcxMjAyMRwwGgYJ
         KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
         ugxQGqHAXpjVQZwsO9n8l8bFCoEevH3AZbz7568XuQm6MK6h7/O9wB4C5oUYddemt5t2Kc8GRhf3
         BDXX5MVZ8G9AUpG1MSqe1CLV2J96rMnwMIJsKeRXr01LYxv/J4kjnktpOC389wmcy2fE4RbPoJne
         P4u2b32c2/V7xsJ7UEjPPSD4i8l2QG6qsUkkx3AyNsjo89PekMfm+Iu/dFKXkdjwXZXPxaL0HrNW
         PTpzek8NS5M5rvF8yaD+eE1zS0I/HicHbPOVvLal0JZyN/f4bp0XJkxZJz6jF5DvBkwIs8/Lz5GK
         nn4XW9Cqjk3equSCJPo5o1Msj8vlLrJYVarqhwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQC26kYe
         LgqjIkF5rvxB2QzTgcd0LVzXOuiVVTZr8Sh57l4jJqbDoIgvaQQrxRSQzD/X+hcmhuwdp9s8zPHS
         JagtUJXiypwNtrzbf6M7ltrWB9sdNrqc99d1gOVRr0Kt5pLTaLe5kkq7dRaQoOIVIJhX9wgynaAK
         HF/SL3mHUytjXggs88AAQa8JH9hEpwG2srN8EsizX6xwQ/p92hM2oLvK5CSMwTx4VBuGod70EOwp
         6Ta1uRLQh6jCCOCWRuZbbz2T3/sOX+sibC4rLIlwfyTkcUopF/bTSdWwknoRskK4dBekFcvN9N+C
         p/qaHYcQd6i2vyor888DLHDPXhSKWhpG`,
		"https://dev-771202.oktapreview.com/app/ibmdev771202_turbo2_1/exkexl6xc9MhzqiC30h7/sso/saml",
		"https://dev-771202.oktapreview.com/app/ibmdev771202_turbo2_1/exkexl6xc9MhzqiC30h7/sso/saml",
		"",
	)

}

func TestParseIdpMetadataOneloginExample(t *testing.T) {
	assertMetadataAttrs(
		t,
		EXAMPLE_ONELOGIN_METADATA,
		"https://app.onelogin.com/saml/metadata/17b77048-3628-4b9b-b68d-d12d46dc417a",
		`MIIDpDCCAoygAwIBAgIGAWMnhv7cMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG
         A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
         MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi03NzEyMDIxHDAaBgkqhkiG9w0BCQEW
         DWluZm9Ab2t0YS5jb20wHhcNMTgwNTAzMTk0MTI4WhcNMjgwNTAzMTk0MjI4WjCBkjELMAkGA1UE
         BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV
         BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtNzcxMjAyMRwwGgYJ
         KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
         ugxQGqHAXpjVQZwsO9n8l8bFCoEevH3AZbz7568XuQm6MK6h7/O9wB4C5oUYddemt5t2Kc8GRhf3
         BDXX5MVZ8G9AUpG1MSqe1CLV2J96rMnwMIJsKeRXr01LYxv/J4kjnktpOC389wmcy2fE4RbPoJne
         P4u2b32c2/V7xsJ7UEjPPSD4i8l2QG6qsUkkx3AyNsjo89PekMfm+Iu/dFKXkdjwXZXPxaL0HrNW
         PTpzek8NS5M5rvF8yaD+eE1zS0I/HicHbPOVvLal0JZyN/f4bp0XJkxZJz6jF5DvBkwIs8/Lz5GK
         nn4XW9Cqjk3equSCJPo5o1Msj8vlLrJYVarqhwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQC26kYe
         LgqjIkF5rvxB2QzTgcd0LVzXOuiVVTZr8Sh57l4jJqbDoIgvaQQrxRSQzD/X+hcmhuwdp9s8zPHS
         JagtUJXiypwNtrzbf6M7ltrWB9sdNrqc99d1gOVRr0Kt5pLTaLe5kkq7dRaQoOIVIJhX9wgynaAK
         HF/SL3mHUytjXggs88AAQa8JH9hEpwG2srN8EsizX6xwQ/p92hM2oLvK5CSMwTx4VBuGod70EOwp
         6Ta1uRLQh6jCCOCWRuZbbz2T3/sOX+sibC4rLIlwfyTkcUopF/bTSdWwknoRskK4dBekFcvN9N+C
         p/qaHYcQd6i2vyor888DLHDPXhSKWhpG`,
		"https://xxxx.onelogin.com/trust/saml2/http-post/sso/uuid",
		"https://xxxx.onelogin.com/trust/saml2/http-redirect/sso/uuid",
		"https://xxxx.onelogin.com/trust/saml2/http-redirect/slo/1234",
	)
}

func TestFailedParses(t *testing.T) {
	output := ParseIdpMetadata("")
	if output.IsValid() {
		t.Fatalf("shouldn't be valid")
	}

	output2 := ParseIdpMetadata(`
	<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
	        entityID=""></md:EntityDescriptor>`)
	if output2.IsValid() {
		t.Fatalf("shouldn't be valid when entityID is missing")
	}
}
