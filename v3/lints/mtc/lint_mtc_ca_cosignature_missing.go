package mtc

import (
	"bytes"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	mtcparser "github.com/zmap/zlint/v3/mtc"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "w_mtc_ca_cosignature_missing",
			Description:   "MTC standalone certificates should carry a cosignature from the CA cosigner",
			Citation:      "draft-ietf-plants-merkle-tree-certs-07, Sections 5.4 and 7.3",
			Source:        lint.MerkleTreeCertificates,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewCACosignatureMissing,
	})
}

// caCosignatureMissing checks that certificates with cosignatures have one
// whose cosigner ID is the CA ID in the issuer, since the CA cosigner's ID is
// the CA ID, and relying parties should require its signature.
//
// Certificates without cosignatures are landmark-relative, and don't need
// one.
type caCosignatureMissing struct{}

func NewCACosignatureMissing() lint.LintInterface {
	return &caCosignatureMissing{}
}

func (l *caCosignatureMissing) CheckApplies(c *x509.Certificate) bool {
	if !mtcparser.IsProofCertificate(c) {
		return false
	}
	parsed, err := mtcparser.ParseCertificate(c)
	return err == nil && len(parsed.Proof.Cosignatures) > 0
}

func (l *caCosignatureMissing) Execute(c *x509.Certificate) *lint.LintResult {
	parsed, err := mtcparser.ParseCertificate(c)
	if err != nil {
		return &lint.LintResult{Status: lint.Fatal, Details: err.Error()}
	}
	for _, cosignature := range parsed.Proof.Cosignatures {
		if bytes.Equal(cosignature.CosignerID, parsed.CAID) {
			return &lint.LintResult{Status: lint.Pass}
		}
	}
	return &lint.LintResult{Status: lint.Warn, Details: "no cosignature from the CA cosigner"}
}
