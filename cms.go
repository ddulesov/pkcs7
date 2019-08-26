// Go Cryptographic Message Syntax (CMS) Signature validation library
// with GOST-R cryptographic functions support
// Copyright (C) 2019 Dmitry Dulesov <dmitry.dulesov(at)gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package pkcs7

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

var (
	ErrUnsupportedAlgorithm = errors.New("x509: unsupported algorithm")
	ErrSignature            = errors.New("cms: signature verify failed")
	ErrSigningTime          = errors.New("cms: signing time failed")
)

// CMS represent Cryptographic Message Syntax (CMS) with Signed-data Content Type
// RFC5652
type CMS struct {
	Content      []byte
	Certificates []*Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

func isCertMatchForIssuerAndSerial(cert *Certificate, ias issuerAndSerial) bool {
	return cert.TBSCertificate.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.TBSCertificate.Issuer.FullBytes, ias.IssuerName.FullBytes) == 0
}

// find certificate by Issuer byte sequese and Serial number
func getCertFromCertsByIssuerAndSerial(certs []*Certificate, ias issuerAndSerial) *Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

// Parse parses a CMS  from the given asn.1 DER data.
func ParseCMS(data []byte) (p7 *CMS, err error) {
	var info contentInfo

	rest, err := asn1.Unmarshal(data, &info)
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}

	}
	if err != nil {
		return nil, err
	}

	switch {
	case info.ContentType.Equal(oidSignedData):
		return parseSignedData(info.Content.Bytes)
		//ToDo  other Content Types parser
	}
	return nil, asn1.SyntaxError{Msg: "Unsupported CMS Content Type"}
}

// CertificateSerial returns  Signer first Certificate serial number.
func (cms *CMS) CertificateSerial() *big.Int {
	if len(cms.Certificates) == 0 {
		return nil
	}

	return cms.Certificates[0].TBSCertificate.SerialNumber
}

// Verify CMS validity.
// check equality CMS content and provided value @content
// check signing time in the range between notBefore-notAfter
// check content digest
// check content signature over provided signer certificates
func (cms *CMS) Verify(content []byte, notBefore, notAfter time.Time) error {
	var err error
	if len(cms.Signers) != 1 {
		return ErrSignature
	}

	if content != nil && bytes.Compare(cms.Content, content) != 0 {
		return ErrSignature
	}

	var signingTime time.Time
	var digest []byte
	var val asn1.RawValue

	for _, signer := range cms.Signers {
		var hashType HashFunction = UnknownHashFunction

		signerCertificate := getCertFromCertsByIssuerAndSerial(cms.Certificates, signer.IssuerAndSerialNumber)

		if signerCertificate == nil {
			return ErrSignature
		}
		//get Content digest and signing time from SignedAttributes
		//
		_, err = asn1.Unmarshal(signer.AuthenticatedAttributes.Raw, &val)
		if err != nil {
			return err
		}

		asn1Data := val.Bytes
		for len(asn1Data) > 0 {
			var attr attribute
			asn1Data, err = asn1.Unmarshal(asn1Data, &attr)
			if err != nil {
				return err
			}

			if attr.Type.Equal(oidAttributeSigningTime) {
				_, err = asn1.Unmarshal(attr.Value.Bytes, &signingTime)
				if err != nil {
					return ErrSigningTime
				}
			}

			if attr.Type.Equal(oidAttributeMessageDigest) {
				_, err = asn1.Unmarshal(attr.Value.Bytes, &digest)
				if err != nil {
					return err
				}
			}
		}

		//log.Printf("signing time %v", signingTime)
		if notBefore.After(signingTime) || notAfter.Before(signingTime) {
			return ErrSigningTime
		}

		hashType = GetHashForOid(signer.DigestAlgorithm.Algorithm)
		if !hashType.Actual() {

			return ErrUnsupportedAlgorithm
		}
		h := hashType.New()

		h.Write(cms.Content)
		computed := h.Sum(nil)

		if bytes.Compare(computed, digest) != 0 {
			return ErrSignature
		}

		signer.AuthenticatedAttributes.Raw[0] = ( asn1.TagSet | 0x20 ) //!hack. replace implicit tag  with SET(17)+Compound(32)

		//HACK!!!
		//openssl use digestAlgorithm  hash functions in all cases
		//verify RFC https://tools.ietf.org/html/rfc5652

		algo := GetSignatureAlgorithmForOid(signer.DigestEncryptionAlgorithm.Algorithm)

		if algo == nil {
			if signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidPublicKeyRSA) {
				for _, item := range signatureAlgorithmDetails {
					if item.hash == hashType && item.pubKeyAlgo == RSA {
						algo = &item
						break
					}
				}
			}

			if algo == nil {
				return ErrUnsupportedAlgorithm
			}
		}

		if algo.hash == UnknownHashFunction {
			algo.hash = hashType
		}

		if err = signerCertificate.CheckSignature(
			algo,
			signer.AuthenticatedAttributes.Raw[:],
			signer.EncryptedDigest[:],
		); err != nil {
			return ErrSignature
		}

	}

	return nil
}

// VerifyCertificates validate CMS signer certificates over proived Certificate Authority
func (cms *CMS) VerifyCertificates(ca []*Certificate) error {
	var err error

	for _, cert := range cms.Certificates {

		for _, ca_cert := range ca {

			if bytes.Compare(ca_cert.TBSCertificate.Subject.FullBytes, cert.TBSCertificate.Issuer.FullBytes) == 0 {
				err = cert.CheckSignatureFrom(ca_cert)
				if err == nil {
					goto Next
				}
			}
			/*
				    //check against all cas
					err = cert.CheckSignatureFrom(ca_cert)
					if err == nil {
						goto Next
					}
			*/
		}

		return ErrSignature
	Next:
	}

	return nil
}
