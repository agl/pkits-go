// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkits contains a subset of the standard PKI testsuite from NIST. See
// http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
package pkits

import (
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"
	"testing"
)

var certCache map[string]*x509.Certificate

func init() {
	certCache = make(map[string]*x509.Certificate)
}

// TestCase represents a PKITS test case. PKITS contains many tests that we
// don't include: tests for S/MIME, CRLs, LDAP etc. Generally tests will be
// omitted but, in the case that it's unclear whether we should pass a test, a
// noSupport string will be set documenting the reason why we fail.
type TestCase struct {
	roots         []string
	intermediates []string
	leaf          string
	fails         bool
	dnsName       string
	noSupport     string
}

var signatureTests = []TestCase{
	{
		leaf: "ValidCertificatePathTest1EE",
	},
	{
		intermediates: []string{"BadSignedCACert"},
		leaf:          "InvalidCASignatureTest2EE",
		fails:         true,
	},
	{
		leaf:  "InvalidEESignatureTest3EE",
		fails: true,
	},
	{
		intermediates: []string{"DSACACert"},
		leaf:          "ValidDSASignaturesTest4EE",
	},
	{
		intermediates: []string{"DSACACert", "DSAParametersInheritedCACert"},
		leaf:          "ValidDSAParameterInheritanceTest5EE",
		noSupport:     "DSA parameter inheritence not supported",
	},
	{
		intermediates: []string{"DSACACert"},
		leaf:          "InvalidDSASignatureTest6EE",
		fails:         true,
	},
}

var validityTests = []TestCase{
	{
		intermediates: []string{"BadnotBeforeDateCACert"},
		leaf:          "InvalidCAnotBeforeDateTest1EE",
		fails:         true,
	},
	{
		leaf:  "InvalidEEnotBeforeDateTest2EE",
		fails: true,
	},
	{
		leaf: "Validpre2000UTCnotBeforeDateTest3EE",
	},
	{
		leaf: "ValidGeneralizedTimenotBeforeDateTest4EE",
	},
	{
		intermediates: []string{"BadnotAfterDateCACert"},
		leaf:          "InvalidCAnotAfterDateTest5EE",
		fails:         true,
	},
	{
		leaf:  "InvalidEEnotAfterDateTest6EE",
		fails: true,
	},
	{
		leaf:  "Invalidpre2000UTCEEnotAfterDateTest7EE",
		fails: true,
	},
	{
		leaf: "ValidGeneralizedTimenotAfterDateTest8EE",
	},
}

var nameChainingTests = []TestCase{
	{
		leaf:      "InvalidNameChainingTest1EE",
		fails:     true,
		noSupport: "unclear if we should be strict here",
	},
	{
		intermediates: []string{"NameOrderingCACert"},
		leaf:          "InvalidNameChainingOrderTest2",
		fails:         true,
		noSupport:     "unclear if we should be strict here",
	},
	// We cheat on the following tests and pass because of key identifiers
	// rather than because we're doing the name matching correctly.
	{
		leaf: "ValidNameChainingWhitespaceTest3EE",
	},
	{
		leaf: "ValidNameChainingWhitespaceTest4EE",
	},
	{
		leaf: "ValidNameChainingCapitalizationTest5EE",
	},
	{
		intermediates: []string{"UIDCACert"},
		leaf:          "ValidNameUIDsTest6EE",
	},
	{
		intermediates: []string{"RFC3280MandatoryAttributeTypesCACert"},
		leaf:          "ValidRFC3280MandatoryAttributeTypesTest7EE",
	},
	{
		intermediates: []string{"RFC3280OptionalAttributeTypesCACert"},
		leaf:          "ValidRFC3280OptionalAttributeTypesTest8EE",
	},
	{
		intermediates: []string{"UTF8StringEncodedNamesCACert"},
		leaf:          "ValidUTF8StringEncodedNamesTest9EE",
	},
	{
		intermediates: []string{"RolloverfromPrintableStringtoUTF8StringCACert"},
		leaf:          "ValidRolloverfromPrintableStringtoUTF8StringTest10EE",
	},
	{
		intermediates: []string{"UTF8StringCaseInsensitiveMatchCACert"},
		leaf:          "ValidUTF8StringCaseInsensitiveMatchTest11EE",
	},
}

var selfIssuedTests = []TestCase{
	{
		intermediates: []string{"BasicSelfIssuedNewKeyOldWithNewCACert", "BasicSelfIssuedNewKeyCACert"},
		leaf:          "ValidBasicSelfIssuedOldWithNewTest1EE",
	},
	{
		intermediates: []string{"BasicSelfIssuedNewKeyOldWithNewCACert", "BasicSelfIssuedNewKeyCACert"},
		leaf:          "InvalidBasicSelfIssuedOldWithNewTest2EE",
		noSupport:     "revocation",
	},
	{
		intermediates: []string{"BasicSelfIssuedOldKeyNewWithOldCACert", "BasicSelfIssuedOldKeyCACert"},
		leaf:          "ValidBasicSelfIssuedNewWithOldTest3EE",
	},
	{
		intermediates: []string{"BasicSelfIssuedOldKeyCACert", "BasicSelfIssuedOldKeyNewWithOldCACert"},
		leaf:          "ValidBasicSelfIssuedNewWithOldTest4EE",
	},
	{
		intermediates: []string{"BasicSelfIssuedOldKeyCACert", "BasicSelfIssuedOldKeyNewWithOldCACert"},
		leaf:          "InvalidBasicSelfIssuedNewWithOldTest5EE",
		fails:         true,
		noSupport:     "revocation",
	},
	// Several tests omitted becasue they cover CRL signing, which we don't
	// support.
}

var basicConstraintsTests = []TestCase{
	{
		intermediates: []string{"MissingbasicConstraintsCACert"},
		leaf:          "InvalidMissingbasicConstraintsTest1EE",
		fails:         true,
	},
	{
		intermediates: []string{"basicConstraintsCriticalcAFalseCACert"},
		leaf:          "InvalidcAFalseTest2EE",
		fails:         true,
	},
	{
		intermediates: []string{"basicConstraintsNotCriticalcAFalseCACert"},
		leaf:          "InvalidcAFalseTest3EE",
		fails:         true,
	},
	{
		intermediates: []string{"basicConstraintsNotCriticalCACert"},
		leaf:          "ValidbasicConstraintsNotCriticalTest4EE",
	},
	{
		intermediates: []string{"pathLenConstraint0CACert", "pathLenConstraint0subCACert"},
		leaf:          "InvalidpathLenConstraintTest5EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint0CACert", "pathLenConstraint0subCACert"},
		leaf:          "InvalidpathLenConstraintTest6EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint0CACert"},
		leaf:          "ValidpathLenConstraintTest7EE",
	},
	{
		intermediates: []string{"pathLenConstraint0CACert"},
		leaf:          "ValidpathLenConstraintTest8EE",
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA0Cert", "pathLenConstraint6subsubCA00Cert"},
		leaf:          "InvalidpathLenConstraintTest9EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA0Cert", "pathLenConstraint6subsubCA00Cert"},
		leaf:          "InvalidpathLenConstraintTest10EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA1Cert", "pathLenConstraint6subsubCA11Cert", "pathLenConstraint6subsubsubCA11XCert"},
		leaf:          "InvalidpathLenConstraintTest11EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA1Cert", "pathLenConstraint6subsubCA11Cert", "pathLenConstraint6subsubsubCA11XCert"},
		leaf:          "InvalidpathLenConstraintTest12EE",
		fails:         true,
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA4Cert", "pathLenConstraint6subsubCA41Cert", "pathLenConstraint6subsubsubCA41XCert"},
		leaf:          "ValidpathLenConstraintTest13EE",
	},
	{
		intermediates: []string{"pathLenConstraint6CACert", "pathLenConstraint6subCA4Cert", "pathLenConstraint6subsubCA41Cert", "pathLenConstraint6subsubsubCA41XCert"},
		leaf:          "ValidpathLenConstraintTest14EE",
	},
	{
		intermediates: []string{"pathLenConstraint0CACert", "pathLenConstraint0SelfIssuedCACert"},
		leaf:          "ValidSelfIssuedpathLenConstraintTest15EE",
		noSupport:     "we don't correctly count self-signed certificates in the path",
	},
	// Skipping tests 16 and 17 for the same reason as 15.
}

var nameConstraintsTests = []TestCase{
	// We skip tests 1..29 because they deal with DN and RFC822 constraints
	// that we don't implement.
	{
		intermediates: []string{"nameConstraintsDNS1CACert"},
		leaf:          "ValidDNSnameConstraintsTest30EE",
		dnsName:       "testserver.testcertificates.gov",
	},
	{
		intermediates: []string{"nameConstraintsDNS1CACert"},
		leaf:          "InvalidDNSnameConstraintsTest31EE",
		fails:         true,
		dnsName:       "testserver.invalidcertificates.gov",
	},
	// Tests 31 and 32 omitted because we don't support excluded names.
}

func TestSignatureVerification(t *testing.T) {
	runTests(t, signatureTests)
}

func TestValidityChecking(t *testing.T) {
	runTests(t, validityTests)
}

func TestNameChaining(t *testing.T) {
	runTests(t, nameChainingTests)
}

func TestSelfIssued(t *testing.T) {
	runTests(t, selfIssuedTests)
}

func TestBasicConstraints(t *testing.T) {
	runTests(t, basicConstraintsTests)
}

func TestNameConstraints(t *testing.T) {
	runTests(t, nameConstraintsTests)
}

func loadCert(fileName string) *x509.Certificate {
	if cert, ok := certCache[fileName]; ok {
		return cert
	}

	derBytes, err := ioutil.ReadFile(filepath.Join("pkits", "certs", fileName) + ".crt")
	if err != nil {
		panic("Failed to load " + fileName + ": " + err.Error())
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic("Failed to load " + fileName + ": " + err.Error())
	}

	certCache[fileName] = cert
	return cert
}

func loadCerts(fileNames []string) *x509.CertPool {
	pool := x509.NewCertPool()

	for _, fileName := range fileNames {
		pool.AddCert(loadCert(fileName))
	}
	return pool
}

func runTests(t *testing.T, tests []TestCase) {
	for i, test := range tests {
		if len(test.noSupport) > 0 {
			continue
		}

		roots := test.roots
		if len(roots) == 0 {
			roots = []string{"TrustAnchorRootCertificate"}
		}

		intermediates := test.intermediates
		if len(intermediates) == 0 {
			intermediates = []string{"GoodCACert"}
		}

		opts := x509.VerifyOptions{
			Intermediates: loadCerts(intermediates),
			Roots:         loadCerts(roots),
			DNSName:       test.dnsName,
		}

		leaf := loadCert(test.leaf)
		_, err := leaf.Verify(opts)

		if err != nil && !test.fails {
			t.Errorf("#%d: failed with '%s' for %+v", i, err, test)
		} else if err == nil && test.fails {
			t.Errorf("#%d: unexpected pass for %+v", i, test)
		}
	}
}
