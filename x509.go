package pkcs7

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
	"time"

	"github.com/ddulesov/gogost/gost3410"
)

type unsignedData []byte
type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type Certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	var cert Certificate
	rest, err := asn1.Unmarshal(asn1Data, &cert)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return &cert, nil
}

/*
func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {

}
*/

func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}

//ToDo create and store PublicKey in certificate
//ToDo concern algo parameters for GOST cryptography . adjust PublicKey ParamSet according to them
func checkSignature(algo *SignatureAlgorithm, signed, signature []byte, pubKey []byte) error {

	if algo == nil || !algo.hash.Actual() || !algo.pubKeyAlgo.Actual() {
		return ErrUnsupportedAlgorithm
	}

	h := algo.hash.New()
	h.Write(signed)
	digest := h.Sum(nil)

	switch algo.pubKeyAlgo {
	case GOSTR3410_2001: // or GOSTR3410_2012_256
		curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()

		pk, err := gost3410.NewPublicKey(curve, gost3410.Mode2001, pubKey)
		if err != nil {
			log.Print(err)
			return ErrSignature
		}

		Reverse(digest)

		ok, _ := pk.VerifyDigest(digest, signature[:])

		if !ok {
			return ErrSignature
		}
		/*  GOSTR3410_2012_256 is the same as GOSTR3410_2001
		case GOSTR3410_2012_256:

			curve := gost3410.CurveIdGostR34102001CryptoProAParamSet()


			pk, err := gost3410.NewPublicKey(curve, gost3410.Mode2001, pubKey)
			if err != nil {
				log.Print(err)
				return ErrSignature
			}

			Reverse(digest)



			ok, _ := pk.VerifyDigest(digest, signature[:])

			if !ok {
				log.Print("public key digest failed.")
				return ErrSignature
			}
		*/
	case GOSTR3410_2012_512:
		curve := gost3410.CurveIdtc26gost341012512paramSetA()

		pk, err := gost3410.NewPublicKey(curve, gost3410.Mode2012, pubKey)
		if err != nil {
			log.Print(err)
			return ErrSignature
		}

		Reverse(digest)

		ok, _ := pk.VerifyDigest(digest, signature[:])

		if !ok {
			return ErrSignature
		}

	case RSA:
		//see. https://golang.org/src/crypto/x509/x509.go?s=27969:28036#L800

		p := new(pkcs1PublicKey)
		rest, err := asn1.Unmarshal(pubKey, p)
		if err != nil {
			log.Print(err)
			return err
		}

		if len(rest) != 0 {
			return errors.New("x509: trailing data after RSA public key")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return rsa.VerifyPKCS1v15(pub, algo.hash.CryptoHash(), digest, signature)

	default:
		return ErrUnsupportedAlgorithm
	}

	return nil

}

func (c *Certificate) CheckSignature(algo *SignatureAlgorithm, signed, signature []byte) error {

	var err error
	var pubKey []byte

	if algo == nil {
		return ErrSignature
	}

	if algo.pubKeyAlgo == RSA {
		pubKey = c.TBSCertificate.PublicKey.PublicKey.RightAlign()

	} else {
		var v asn1.RawValue

		if _, err = asn1.Unmarshal(c.TBSCertificate.PublicKey.PublicKey.Bytes, &v); err != nil {
			return err
		}
		pubKey = v.Bytes

	}

	return checkSignature(algo, signed, signature, pubKey)
}

func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {

	if parent == nil {
		return nil
	}

	if bytes.Compare(c.TBSCertificate.Issuer.FullBytes, parent.TBSCertificate.Subject.FullBytes) != 0 {
		return ErrSignature
	}

	/*
		if (parent.Version == 3 && !parent.BasicConstraintsValid ||
			parent.BasicConstraintsValid && !parent.IsCA) &&
			!bytes.Equal(c.RawSubjectPublicKeyInfo, entrustBrokenSPKI) {
			return ConstraintViolationError{}
		}

		if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
			return ConstraintViolationError{}
		}

		if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
			return ErrUnsupportedAlgorithm
		}
	*/

	algo := GetSignatureAlgorithmForOid(c.TBSCertificate.SignatureAlgorithm.Algorithm)

	if algo == nil {
		log.Print("algo not fount", c.TBSCertificate.SignatureAlgorithm.Algorithm)
	}

	return parent.CheckSignature(algo, c.TBSCertificate.Raw, c.SignatureValue.RightAlign())
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type GOSTCryptoProParameters struct {
	ParamSet []asn1.ObjectIdentifier
}

type publicKeyInfo struct {
	//Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type signedAttrs struct {
	Raw asn1.RawContent
}

type signerInfo struct {
	Version               int `asn1:"default:1"`
	IssuerAndSerialNumber issuerAndSerial
	DigestAlgorithm       pkix.AlgorithmIdentifier
	//AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	AuthenticatedAttributes   signedAttrs `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
	var v []*Certificate

	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	asn1Data := val.Bytes

	for len(asn1Data) > 0 {
		cert := new(Certificate)
		var err error
		asn1Data, err = asn1.Unmarshal(asn1Data, cert)
		if err != nil {
			return nil, err
		}
		v = append(v, cert)
	}
	return v, nil

	//return x509.ParseCertificates(val.Bytes)
}

/*
type SignedData struct {
	sd            signedData
	certs         []*x509.Certificate
	messageDigest []byte
}
*/

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}
type SignerInfoConfig struct {
	ExtraSignedAttributes []Attribute
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

func parseSignedData(data []byte) (*CMS, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)

	/* NEWVER */
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}

	return &CMS{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}
