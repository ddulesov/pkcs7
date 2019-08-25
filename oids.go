package pkcs7

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"hash"

	"github.com/ddulesov/gogost/gost28147"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost34112012512"
	"github.com/ddulesov/gogost/gost341194"
)

var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	oidSignatureMD2WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}

	oidISOSignatureSHA1WithRSA  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	//GOST signature algorithms   ,
	oidSignatureGOSTR3410_2001              = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
	oidSignatureGOSTR3410_2001_GOSTR3411_94 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}

	//algorithm: GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit) (1.2.643.7.1.1.3.2)
	oidSignatureGOSTR3410_2012_256_GOSTR3411_12 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	//algorithm: GOST R 34.10-2012 (256 bit) (1.2.643.7.1.1.1.1)
	oidSignatureGOSTR3410_2012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}

	//algorithm: GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit) (1.2.643.7.1.1.3.3)
	oidSignatureGOSTR3410_2012_512_GOSTR3411_12 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	//algorithm: GOST R 34.10-2012 (512 bit) (1.2.643.7.1.1.1.2)
	oidSignatureGOSTR3410_2012_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

	//szOID_tc26_gost_3410_12_256_paramSetA	"1.2.643.7.1.2.1.1.1"
	//oidSignatureGOSTR3410_12_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	//szOID_tc26_gost_3410_12_512_paramSetA	"1.2.643.7.1.2.1.2.1"
	//algorithm: GOST R 34.10-2012 with 512 bit modulus (1.2.643.7.1.1.1.2)
	//oidSignatureGOSTR3410_12_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}

	//standard hash functions
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	//GOST hash function oid
	oidGOST_R341194 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}
	//stribog
	oidGOST_R341112_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	oidGOST_R341112_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

	oidUnknown = asn1.ObjectIdentifier{0}
)

type HashFunction int

const (
	UnknownHashFunction HashFunction = iota
	SHA1
	SHA256
	SHA384
	SHA512
	GOSTR3411_94
	GOSTR3411_2012_256 //Stribog GOST R 34.11-2012 256-bit
	GOSTR3411_2012_512 //Stribog GOST R 34.11-2012 512-bit

)

func (h HashFunction) Actual() bool {
	return (h != UnknownHashFunction)
}

func (h HashFunction) CryptoHash() crypto.Hash {
	switch h {
	case SHA1:
		return crypto.SHA1
	case SHA256:
		return crypto.SHA256
	case SHA384:
		return crypto.SHA384
	case SHA512:
		return crypto.SHA512
	}
	return crypto.Hash(0)
}

func (h HashFunction) New() hash.Hash {
	switch h {
	case SHA1:
		return crypto.SHA1.New()
	case SHA256:
		return crypto.SHA256.New()
	case SHA384:
		return crypto.SHA384.New()
	case SHA512:
		return crypto.SHA512.New()
	case GOSTR3411_94:
		return gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)
	case GOSTR3411_2012_256:
		return gost34112012256.New()
	case GOSTR3411_2012_512:
		return gost34112012512.New()
	}
	return nil
}

type PublicKeyAlgorithm int

const (
	UnknownAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	RSAPSS
	ECDSA
	GOSTR3410_2001
	GOSTR3410_2012_512
)

const GOSTR3410_2012_256 = GOSTR3410_2001

func (h PublicKeyAlgorithm) Actual() bool {
	return (h != UnknownAlgorithm && h != RSAPSS && h != ECDSA)
}

type CryptoFamily int

const (
	FRSA CryptoFamily = iota
	FDSA
	FECDSA
	FGOSTR3410
)

type SignatureAlgorithm struct {
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo PublicKeyAlgorithm
	hash       HashFunction
}

func (algo *SignatureAlgorithm) Family() CryptoFamily {
	if algo.pubKeyAlgo == GOSTR3410_2001 || algo.pubKeyAlgo == GOSTR3410_2012_256 || algo.pubKeyAlgo == GOSTR3410_2012_512 {
		return FGOSTR3410
	}

	if algo.pubKeyAlgo == RSA || algo.pubKeyAlgo == RSAPSS {
		return FRSA
	}
	if algo.pubKeyAlgo == ECDSA {
		return FECDSA
	}
	if algo.pubKeyAlgo == DSA {
		return FDSA
	}
	return CryptoFamily(0)
}

var signatureAlgorithmDetails = []SignatureAlgorithm{

	{"SHA1-RSA", oidSignatureSHA1WithRSA, RSA, SHA1},
	{"SHA1-RSA", oidISOSignatureSHA1WithRSA, RSA, SHA1},
	{"SHA256-RSA", oidSignatureSHA256WithRSA, RSA, SHA256},
	{"SHA384-RSA", oidSignatureSHA384WithRSA, RSA, SHA384},
	{"SHA512-RSA", oidSignatureSHA512WithRSA, RSA, SHA512},
	/*
		{"SHA256-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA256},
		{"SHA384-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA384},
		{"SHA512-RSAPSS", oidSignatureRSAPSS, RSAPSS, SHA512},

		{ "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1},
		{ "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256},
		{ "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1},
		{ "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256},
		{ "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384},
		{ "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512},
	*/
	//GOST-R  https://www.cryptopro.ru/sites/default/files/products/tls/tk26iok.pdf
	{"GOST-3410_2001", oidSignatureGOSTR3410_2001, GOSTR3410_2001, UnknownHashFunction},
	{"GOST-3410_2001-3411_94", oidSignatureGOSTR3410_2001_GOSTR3411_94, GOSTR3410_2001, GOSTR3411_94},

	{"GOST-3410_12_256", oidSignatureGOSTR3410_2012_256, GOSTR3410_2012_256, UnknownHashFunction},
	{"GOST-3410_12_256-3411_12", oidSignatureGOSTR3410_2012_256_GOSTR3411_12, GOSTR3410_2012_256, GOSTR3411_2012_256},

	{"GOST-3410_12_512", oidSignatureGOSTR3410_2012_512, GOSTR3410_2012_512, UnknownHashFunction},
	{"GOST-3410_12_512-3411_12", oidSignatureGOSTR3410_2012_512_GOSTR3411_12, GOSTR3410_2012_512, GOSTR3411_2012_512},
}

func GetSignatureAlgorithmForOid(oid asn1.ObjectIdentifier) *SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if details.oid.Equal(oid) {
			return &details
		}
	}

	return nil
}

var hashFunctionDetails = []struct {
	name string
	oid  asn1.ObjectIdentifier
	hash HashFunction
}{
	{"SHA1", oidSHA1, SHA1},
	{"SHA256", oidSHA256, SHA256},
	{"SHA384", oidSHA384, SHA384},
	{"SHA512", oidSHA512, SHA512},
	{"GOST-R34.11.94", oidGOST_R341194, GOSTR3411_94},
	{"GOST-R34.11.12_256", oidGOST_R341112_256, GOSTR3411_2012_256},
	{"GOST-R34.11.12_512", oidGOST_R341112_512, GOSTR3411_2012_512},
}

func GetHashForOid(oid asn1.ObjectIdentifier) HashFunction {

	for _, v := range hashFunctionDetails {
		if oid.Equal(v.oid) {
			return v.hash
		}
	}
	return UnknownHashFunction
}
