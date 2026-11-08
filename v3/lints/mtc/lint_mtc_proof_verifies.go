package mtc

import (
	"bytes"
	"crypto/mldsa"
	stdx509 "crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	mtcparser "github.com/zmap/zlint/v3/mtc"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterCertificateLint(&lint.CertificateLint{
		LintMetadata: lint.LintMetadata{
			Name:          "e_mtc_proof_verifies",
			Description:   "MTC proofs verify against the configured cosigners or landmark subtrees",
			Citation:      "draft-ietf-plants-merkle-tree-certs-07, Section 7.2",
			Source:        lint.MerkleTreeCertificates,
			EffectiveDate: util.ZeroDate,
		},
		Lint: NewProofVerifies,
	})
}

// proofVerifies verifies an MTC proof like a relying party would, using
// trusted cosigners or subtrees from the configuration. It only applies if
// Mode is set.
//
// In "standalone" mode, the certificate must carry a valid cosignature from
// every required cosigner, and from at least one configured cosigner.
// Cosignatures from unconfigured cosigners are ignored.
//
// In "landmark" mode, the certificate must carry no cosignatures, and its
// subtree hash must match the configured subtree with the same start and end.
type proofVerifies struct {
	// Mode is "standalone", "landmark", or empty to disable the lint.
	Mode string
	// Cosigners are the trusted cosigners, for standalone mode.
	Cosigners []mtcCosigner
	// Subtrees are the trusted landmark subtrees, for landmark mode.
	Subtrees []landmarkSubtree
}

type mtcCosigner struct {
	// ID is the ASCII representation of the cosigner ID, e.g. "32473.1".
	ID string
	// PublicKey is the base64-encoded DER SubjectPublicKeyInfo of the
	// cosigner's ML-DSA public key.
	PublicKey string
	// Required makes the lint fail if the certificate has no cosignature
	// from this cosigner.
	Required bool
}

type landmarkSubtree struct {
	Start uint64
	End   uint64
	// Hash is the hex-encoded subtree hash.
	Hash string
}

func NewProofVerifies() lint.LintInterface {
	return &proofVerifies{}
}

func (l *proofVerifies) Configure() interface{} {
	return l
}

func (l *proofVerifies) CheckApplies(c *x509.Certificate) bool {
	return l.Mode != "" && mtcparser.IsProofCertificate(c)
}

func (l *proofVerifies) Execute(c *x509.Certificate) *lint.LintResult {
	if l.Mode != "standalone" && l.Mode != "landmark" {
		return &lint.LintResult{Status: lint.Fatal, Details: fmt.Sprintf("unknown mode %q", l.Mode)}
	}
	parsed, err := mtcparser.ParseCertificate(c)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}
	hash, err := mtcparser.SubtreeHash(c, parsed)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}
	if l.Mode == "landmark" {
		return l.landmark(parsed, hash)
	}
	return l.standalone(parsed, hash)
}

func (l *proofVerifies) landmark(parsed *mtcparser.Certificate, hash [32]byte) *lint.LintResult {
	p := parsed.Proof
	if len(p.Cosignatures) != 0 {
		return &lint.LintResult{Status: lint.Error, Details: "landmark-relative certificate has cosignatures"}
	}
	for _, s := range l.Subtrees {
		if s.Start != p.Start || s.End != p.End {
			continue
		}
		want, err := hex.DecodeString(s.Hash)
		if err != nil || len(want) != len(hash) {
			return &lint.LintResult{Status: lint.Fatal, Details: fmt.Sprintf("invalid hash for subtree [%d, %d)", s.Start, s.End)}
		}
		if !bytes.Equal(want, hash[:]) {
			return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("subtree [%d, %d) hash is %x, expected %s", p.Start, p.End, hash, s.Hash)}
		}
		return &lint.LintResult{Status: lint.Pass}
	}
	return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("subtree [%d, %d) is not a configured landmark subtree", p.Start, p.End)}
}

func (l *proofVerifies) standalone(parsed *mtcparser.Certificate, hash [32]byte) *lint.LintResult {
	p := parsed.Proof
	logID, err := mtcparser.LogID(parsed)
	if err != nil {
		return &lint.LintResult{Status: lint.Error, Details: err.Error()}
	}
	verified := 0
	for _, cosigner := range l.Cosigners {
		id, err := mtcparser.ParseTrustAnchorID(cosigner.ID)
		if err != nil {
			return &lint.LintResult{Status: lint.Fatal, Details: err.Error()}
		}
		key, err := parseCosignerKey(cosigner.PublicKey)
		if err != nil {
			return &lint.LintResult{Status: lint.Fatal, Details: fmt.Sprintf("cosigner %s: %v", cosigner.ID, err)}
		}
		var signature []byte
		for _, c := range p.Cosignatures {
			if bytes.Equal(c.CosignerID, id) {
				signature = c.Signature
			}
		}
		if signature == nil {
			if cosigner.Required {
				return &lint.LintResult{Status: lint.Error, Details: "missing cosignature from required cosigner " + cosigner.ID}
			}
			continue
		}
		msg, err := mtcparser.CosignedSubtree(id, logID, p.Start, p.End, hash)
		if err != nil {
			return &lint.LintResult{Status: lint.Error, Details: err.Error()}
		}
		if err := mldsa.Verify(key, msg, signature, nil); err != nil {
			return &lint.LintResult{Status: lint.Error, Details: "invalid cosignature from cosigner " + cosigner.ID}
		}
		verified++
	}
	if verified == 0 {
		return &lint.LintResult{Status: lint.Error, Details: "no cosignature from a configured cosigner"}
	}
	return &lint.LintResult{Status: lint.Pass}
}

func parseCosignerKey(s string) (*mldsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	pub, err := stdx509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
	return key, nil
}
