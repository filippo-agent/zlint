package mtc

import (
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	mtcparser "github.com/zmap/zlint/v3/mtc"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_mtc_entry_extension_unrecognized",
			Description:   "MTC log entries must not have extensions of unrecognized types",
			Citation:      "draft-ietf-plants-merkle-tree-certs-07, Sections 5.2.1 and 5.4",
			Source:        lint.MerkleTreeCertificates,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewEntryExtensionUnrecognized,
	})
}

// entryExtensionUnrecognized checks the extensions of the log entry, carried
// in the MTCProof. A CA must not sign a subtree containing an entry with an
// extension_type it does not recognize, and draft-07 defines no extension
// types, so any extension is an error.
type entryExtensionUnrecognized struct{}

func NewEntryExtensionUnrecognized() lint.LintInterface {
	return &entryExtensionUnrecognized{}
}

func (l *entryExtensionUnrecognized) CheckApplies(c *x509.Certificate) bool {
	if !mtcparser.IsProofCertificate(c) {
		return false
	}
	_, err := mtcparser.ParseCertificate(c)
	return err == nil
}

func (l *entryExtensionUnrecognized) Execute(c *x509.Certificate) *lint.LintResult {
	parsed, err := mtcparser.ParseCertificate(c)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal, Details: err.Error()}
	}
	if types := parsed.Proof.EntryExtensionTypes; len(types) > 0 {
		return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("log entry has extensions of unrecognized types %v", types)}
	}
	return &lint.LintResult{Status: lint.Pass}
}
