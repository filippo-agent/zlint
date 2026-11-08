package mtc

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	mtcparser "github.com/zmap/zlint/v3/mtc"
	"github.com/zmap/zlint/v3/test"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	mtcProofAlg     = []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43}
	mtcProofNullAlg = []byte{0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x43, 0x05, 0x00}
	mldsa44Alg      = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
)

// rebuild re-encodes the certificate der, replacing the TBSCertificate
// signature field, the signatureAlgorithm, and the signatureValue contents
// with tbsAlg, alg, and sig, if not nil.
func rebuild(t *testing.T, der, tbsAlg, alg, sig []byte) *x509.Certificate {
	t.Helper()
	input := cryptobyte.String(der)
	var cert, tbs, version, serial, oldTBSAlg, oldAlg cryptobyte.String
	var oldSig []byte
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) ||
		!cert.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&oldAlg, cbasn1.SEQUENCE) ||
		!cert.ReadASN1BitStringAsBytes(&oldSig) ||
		!tbs.ReadASN1Element(&version, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1Element(&serial, cbasn1.INTEGER) ||
		!tbs.ReadASN1Element(&oldTBSAlg, cbasn1.SEQUENCE) {
		t.Fatal("malformed certificate")
	}
	if tbsAlg == nil {
		tbsAlg = oldTBSAlg
	}
	if alg == nil {
		alg = oldAlg
	}
	if sig == nil {
		sig = oldSig
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		b.AddBytes(serial)
		b.AddBytes(tbsAlg)
		b.AddBytes(tbs)
	})
	newTBS := b.BytesOrPanic()
	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddBytes(alg)
		b.AddASN1BitString(sig)
	})
	return &x509.Certificate{Raw: b.BytesOrPanic(), RawTBSCertificate: newTBS}
}

func TestMTCProofAlgorithm(t *testing.T) {
	cosigned := readMTCFile(t, "mtc_magnolia_cosigned.pem")
	for _, tt := range []struct {
		name   string
		tbsAlg []byte
		alg    []byte
		want   lint.LintStatus
	}{
		{"valid", mtcProofAlg, mtcProofAlg, lint.Pass},
		{"NULL parameters in signatureAlgorithm", mtcProofAlg, mtcProofNullAlg, lint.Error},
		{"NULL parameters in signature", mtcProofNullAlg, mtcProofAlg, lint.Error},
		{"NULL parameters in both", mtcProofNullAlg, mtcProofNullAlg, lint.Error},
		{"other signatureAlgorithm", mtcProofAlg, mldsa44Alg, lint.Error},
		{"other signature", mldsa44Alg, mtcProofAlg, lint.Error},
		{"not an MTC", mldsa44Alg, mldsa44Alg, lint.NA},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cert := rebuild(t, cosigned, tt.tbsAlg, tt.alg, nil)
			result := test.TestLintCert("e_mtc_proof_structure_valid", cert, lint.NewEmptyConfig())
			if result.Status != tt.want {
				t.Errorf("got %s (%s), want %s", result.Status, result.Details, tt.want)
			}
		})
	}
}

// encodeProof encodes an MTCProof.
func encodeProof(p *mtcparser.Proof) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(p.EntryExtensions) })
	b.AddUint48(p.Start)
	b.AddUint48(p.End)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(p.InclusionProof) })
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range p.Cosignatures {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(c.CosignerID) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(c.Signature) })
		}
	})
	return b.BytesOrPanic()
}

func TestMTCCACosignatureMissing(t *testing.T) {
	cosigned := readMTCFile(t, "mtc_magnolia_cosigned.pem")
	parsed, err := mtcparser.ParseCertificate(rebuild(t, cosigned, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	// The cosignatures are from 66252.0 and 66252.1, the CA ID.
	if len(parsed.Proof.Cosignatures) != 2 {
		t.Fatalf("got %d cosignatures, want 2", len(parsed.Proof.Cosignatures))
	}
	withoutCA := parsed.Proof
	withoutCA.Cosignatures = withoutCA.Cosignatures[:1]
	onlyCA := parsed.Proof
	onlyCA.Cosignatures = onlyCA.Cosignatures[1:]

	for _, tt := range []struct {
		name string
		cert *x509.Certificate
		want lint.LintStatus
	}{
		{"CA and mirror", rebuild(t, cosigned, nil, nil, nil), lint.Pass},
		{"CA only", rebuild(t, cosigned, nil, nil, encodeProof(&onlyCA)), lint.Pass},
		{"mirror only", rebuild(t, cosigned, nil, nil, encodeProof(&withoutCA)), lint.Warn},
		{"landmark", rebuild(t, readMTCFile(t, "mtc_magnolia_landmark.pem"), nil, nil, nil), lint.NA},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := test.TestLintCert("w_mtc_ca_cosignature_missing", tt.cert, lint.NewEmptyConfig())
			if result.Status != tt.want {
				t.Errorf("got %s (%s), want %s", result.Status, result.Details, tt.want)
			}
		})
	}
}

func TestMTCIssuer(t *testing.T) {
	cosigned := readMTCFile(t, "mtc_magnolia_cosigned.pem")
	// Change the tag of the issuer attribute value from RELATIVE-OID to
	// UTF8String, which keeps all lengths the same.
	attr := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x19, 0x03, 0x0d}
	utf8Attr := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x19, 0x03, 0x0c}
	bad := bytes.Replace(cosigned, attr, utf8Attr, 1)
	if bytes.Equal(bad, cosigned) {
		t.Fatal("issuer attribute not found")
	}
	result := test.TestLintCert("e_mtc_proof_structure_valid", rebuild(t, bad, nil, nil, nil), lint.NewEmptyConfig())
	if result.Status != lint.Error {
		t.Errorf("got %s (%s), want error", result.Status, result.Details)
	}
}

func TestMTCEntryExtensionUnrecognized(t *testing.T) {
	cosigned := readMTCFile(t, "mtc_magnolia_cosigned.pem")
	parsed, err := mtcparser.ParseCertificate(rebuild(t, cosigned, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	withExtensions := parsed.Proof
	// Two extensions, of types 1 and 7.
	withExtensions.EntryExtensions = []byte{0x00, 0x01, 0x00, 0x01, 0xaa, 0x00, 0x07, 0x00, 0x00}

	for _, tt := range []struct {
		name    string
		cert    *x509.Certificate
		want    lint.LintStatus
		details string
	}{
		{"none", rebuild(t, cosigned, nil, nil, nil), lint.Pass, ""},
		{"landmark", rebuild(t, readMTCFile(t, "mtc_magnolia_landmark.pem"), nil, nil, nil), lint.Pass, ""},
		{"two", rebuild(t, cosigned, nil, nil, encodeProof(&withExtensions)), lint.Error, "[1 7]"},
		{"malformed proof", rebuild(t, cosigned, nil, nil, []byte{0}), lint.NA, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := test.TestLintCert("e_mtc_entry_extension_unrecognized", tt.cert, lint.NewEmptyConfig())
			if result.Status != tt.want {
				t.Errorf("got %s (%s), want %s", result.Status, result.Details, tt.want)
			}
			if !strings.Contains(result.Details, tt.details) {
				t.Errorf("details %q do not contain %q", result.Details, tt.details)
			}
		})
	}
}
