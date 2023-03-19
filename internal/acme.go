package internal

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/acme"
)

type Prober struct {
	Client   *acme.Client
	errors   []error
	ChalType string

	CfAuth CloudflareAuth
}

func (p *Prober) errorf(format string, a ...interface{}) {
	err := fmt.Errorf(format, a...)
	log.Print(err)
	p.errors = append(p.errors, err)
}
func (p *Prober) fulfill(ctx context.Context, z *acme.Authorization) error {
	var chal *acme.Challenge
	for i, c := range z.Challenges {
		log.Printf("challenge %d: %+v", i, c)
		if c.Type == p.ChalType {
			log.Printf("picked %s for authz %s", c.URI, z.URI)
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("challenge type %q wasn't offered for authz %s", p.ChalType, z.URI)
	}

	switch chal.Type {
	case "dns-01":
		result := p.runDNS01(ctx, z, chal)
		p.CfAuth.DelChallengeRecord(ctx)
		fmt.Println("do cleaned!!")
		return result
	default:
		return fmt.Errorf("unknown challenge type %q", chal.Type)
	}
}

func (p *Prober) RunOrder(ctx context.Context, identifiers []acme.AuthzID) (crypto.Signer, string) {
	// Create a new order and pick a challenge.
	// Note that Let's Encrypt will reply with 400 error:malformed
	// "NotBefore and NotAfter are not supported" when providing a NotAfter
	// value like WithOrderNotAfter(time.Now().Add(24 * time.Hour)).
	o, err := p.Client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		log.Fatalf("AuthorizeOrder: %v", err)
	}

	var zurls []string
	for _, u := range o.AuthzURLs {
		z, err := p.Client.GetAuthorization(ctx, u)
		if err != nil {
			log.Fatalf("GetAuthorization(%q): %v", u, err)
		}
		log.Printf("%+v", z)
		if z.Status != acme.StatusPending {
			log.Printf("authz status is %q; skipping", z.Status)
			continue
		}
		if err := p.fulfill(ctx, z); err != nil {
			log.Fatalf("fulfill(%s): %v", z.URI, err)
		}
		zurls = append(zurls, z.URI)
		log.Printf("authorized for %+v", z.Identifier)
	}

	log.Print("all challenges are done")
	if _, err := p.Client.WaitOrder(ctx, o.URI); err != nil {
		log.Fatalf("WaitOrder(%q): %v", o.URI, err)
	}
	csr, certkey := newCSR(identifiers)

	der, curl, err := p.Client.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		log.Fatalf("CreateOrderCert: %v", err)
	}
	log.Printf("cert URL: %s", curl)
	if err := checkCert(der, identifiers); err != nil {
		p.errorf("invalid cert: %v", err)
	}

	// afterOrderCert(certkey,curl)

	// fmt.Println(certkey)
	// fmt.Println("=====")
	// // saveFile("ssl.csr", csr)
	// prikey, _ := EncodeKey(certkey, certkey.Public())
	// saveFile("ssl.key", []byte(prikey))
	// // saveFile("ssl.pub.key", []byte(pubkey))
	// err = DownloadFile("ssl.cer", curl)
	// if err != nil {
	// 	log.Fatalf("download file err: %v", err)
	// }

	// Deactivate all authorizations we satisfied earlier.
	for _, v := range zurls {
		if err := p.Client.RevokeAuthorization(ctx, v); err != nil {
			p.errorf("RevokAuthorization(%q): %v", v, err)
			continue
		}
	}
	// Deactivate the account. We don't need it for any further calls.
	if err := p.Client.DeactivateReg(ctx); err != nil {
		p.errorf("DeactivateReg: %v", err)
	}
	// Try revoking the issued cert using its private key.
	if err := p.Client.RevokeCert(ctx, certkey, der[0], acme.CRLReasonCessationOfOperation); err != nil {
		p.errorf("RevokeCert: %v", err)
	}

	return certkey, curl
}

func (p *Prober) runDNS01(ctx context.Context, z *acme.Authorization, chal *acme.Challenge) error {
	token, err := p.Client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("DNS01ChallengeRecord: %v", err)
	}

	name := fmt.Sprintf("_acme-challenge.%s", z.Identifier.Value)
	err = p.CfAuth.UpdateOrInsertChallengeRecord(ctx, name, token)
	if err != nil {
		return err
	}

	if _, err := p.Client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("Accept(%q): %v", chal.URI, err)
	}
	_, zerr := p.Client.WaitAuthorization(ctx, z.URI)
	return zerr
}

func checkCert(derChain [][]byte, id []acme.AuthzID) error {
	if len(derChain) == 0 {
		return errors.New("cert chain is zero bytes")
	}
	for i, b := range derChain {
		crt, err := x509.ParseCertificate(b)
		if err != nil {
			return fmt.Errorf("%d: ParseCertificate: %v", i, err)
		}
		log.Printf("%d: serial: 0x%s", i, crt.SerialNumber)
		log.Printf("%d: subject: %s", i, crt.Subject)
		log.Printf("%d: issuer: %s", i, crt.Issuer)
		log.Printf("%d: expires in %.1f day(s)", i, time.Until(crt.NotAfter).Hours()/24)
		if i > 0 { // not a leaf cert
			continue
		}
		p := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		log.Printf("%d: leaf:\n%s", i, pem.EncodeToMemory(p))
		for _, v := range id {
			if err := crt.VerifyHostname(v.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

func newCSR(identifiers []acme.AuthzID) ([]byte, crypto.Signer) {
	var csr x509.CertificateRequest
	for _, id := range identifiers {
		switch id.Type {
		case "dns":
			csr.DNSNames = append(csr.DNSNames, id.Value)
		// case "ip":
		// 	csr.IPAddresses = append(csr.IPAddresses, net.ParseIP(id.Value))
		default:
			panic(fmt.Sprintf("newCSR: unknown identifier type %q", id.Type))
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("newCSR: ecdsa.GenerateKey for a cert: %v", err))
	}
	b, err := x509.CreateCertificateRequest(rand.Reader, &csr, k)
	if err != nil {
		panic(fmt.Sprintf("newCSR: x509.CreateCertificateRequest: %v", err))
	}
	return b, k
}
