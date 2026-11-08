package mtc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var trustAnchorIDAttributeOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

// ParseTrustAnchorID parses the ASCII representation of a trust anchor ID,
// such as "32473.1", and returns its binary representation, as defined in
// Section 4 of draft-ietf-tls-trust-anchor-ids.
func ParseTrustAnchorID(s string) ([]byte, error) {
	var b []byte
	for _, arc := range strings.Split(s, ".") {
		if arc == "" || (len(arc) > 1 && arc[0] == '0') || arc[0] == '+' {
			return nil, fmt.Errorf("invalid trust anchor ID %q", s)
		}
		n, err := strconv.ParseUint(arc, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid trust anchor ID %q: %w", s, err)
		}
		b = appendBase128(b, n)
	}
	return b, nil
}

func appendBase128(b []byte, n uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(n & 0x7f)
	for n >>= 7; n > 0; n >>= 7 {
		i--
		tmp[i] = byte(n&0x7f) | 0x80
	}
	return append(b, tmp[i:]...)
}

// trustAnchorIDString returns the ASCII representation of a binary trust
// anchor ID. Components larger than 2^64-1 are rejected.
func trustAnchorIDString(id []byte) (string, error) {
	if len(id) == 0 {
		return "", errors.New("empty trust anchor ID")
	}
	var arcs []string
	for len(id) > 0 {
		if id[0] == 0x80 {
			return "", errors.New("trust anchor ID component is not minimally encoded")
		}
		var n uint64
		for {
			if len(id) == 0 {
				return "", errors.New("truncated trust anchor ID")
			}
			if n > (1<<64-1)>>7 {
				return "", errors.New("trust anchor ID component is too large")
			}
			c := id[0]
			id = id[1:]
			n = n<<7 | uint64(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		arcs = append(arcs, strconv.FormatUint(n, 10))
	}
	return strings.Join(arcs, "."), nil
}

// caID returns the binary CA ID from the issuer of a DER-encoded
// TBSCertificate, which must be a single relative distinguished name with a
// single id-rdna-trustAnchorID attribute, as in Section 5.1 of
// draft-ietf-plants-merkle-tree-certs-07.
func caID(rawTBS []byte) ([]byte, error) {
	s := cryptobyte.String(rawTBS)
	var tbs, issuer, rdn, attr, id cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.SkipASN1(cbasn1.INTEGER) || !tbs.SkipASN1(cbasn1.SEQUENCE) ||
		!tbs.ReadASN1(&issuer, cbasn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate")
	}
	if !issuer.ReadASN1(&rdn, cbasn1.SET) || !issuer.Empty() ||
		!rdn.ReadASN1(&attr, cbasn1.SEQUENCE) || !rdn.Empty() ||
		!attr.ReadASN1ObjectIdentifier(&oid) || !oid.Equal(trustAnchorIDAttributeOID) ||
		!attr.ReadASN1(&id, cbasn1.Tag(13)) || !attr.Empty() { // RELATIVE-OID
		return nil, errors.New("issuer is not a single trust anchor ID attribute")
	}
	if _, err := trustAnchorIDString(id); err != nil {
		return nil, fmt.Errorf("invalid issuer CA ID: %w", err)
	}
	return id, nil
}

// LogID returns the binary log ID of the issuance log of the certificate,
// constructed from the CA ID in the issuer and the log number in the serial
// number, as in step 6 of Section 7.2 of
// draft-ietf-plants-merkle-tree-certs-07.
func LogID(parsed *Certificate) ([]byte, error) {
	id, err := caID(parsed.TBSCertificate)
	if err != nil {
		return nil, err
	}
	logNumber := parsed.Serial >> 48
	if logNumber == 0 {
		return nil, errors.New("serial number has log number zero")
	}
	logID := append([]byte(nil), id...)
	logID = appendBase128(logID, 0)
	logID = appendBase128(logID, logNumber)
	return logID, nil
}

// CosignedSubtree returns the message signed by a cosigner for the subtree
// [start, end) of the log, with a zero timestamp, as defined in Section 5.3.1
// of draft-ietf-plants-merkle-tree-certs-07.
func CosignedSubtree(cosignerID, logID []byte, start, end uint64, hash [sha256.Size]byte) ([]byte, error) {
	name, err := trustAnchorIDString(cosignerID)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner ID: %w", err)
	}
	origin, err := trustAnchorIDString(logID)
	if err != nil {
		return nil, fmt.Errorf("invalid log ID: %w", err)
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddBytes([]byte("subtree/v1\n\x00"))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("oid/1.3.6.1.4.1." + name))
	})
	b.AddUint64(0) // timestamp
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("oid/1.3.6.1.4.1." + origin))
	})
	b.AddUint64(start)
	b.AddUint64(end)
	b.AddBytes(hash[:])
	return b.Bytes()
}
