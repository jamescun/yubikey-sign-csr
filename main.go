package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/term"
)

func main() {
	var (
		listKeys = flag.Bool("list-keys", false, "list yubikeys")
		keyID    = flag.Int("key", 0, "id of yubikey from --list-keys")
		slotType = flag.String("slot", "9c", "key type of slot on yubikey")
		csrPath  = flag.String("csr", "csr.pem", "path to certificate signing request")
		isCA     = flag.Bool("ca", false, "certificate is to be an authority")
		isServer = flag.Bool("server", false, "certificate is to be used as a server")
		isClient = flag.Bool("client", false, "certificate is to be used as a client")
		validity = flag.String("validity", "8766h", "duration certificate will be valid for")
	)

	flag.Parse()

	cards, err := piv.Cards()
	if err != nil {
		exitError(1, "could not list keys:", err)
	}

	if len(cards) < 1 {
		exitError(1, "no yubikeys found")
	}

	if *listKeys {
		for i, card := range cards {
			fmt.Printf("%d: %s\n", i, card)
		}

		return
	}

	if *keyID > len(cards) {
		exitError(1, "no key id %d", *keyID)
	}

	slot, ok := getSlot(*slotType)
	if !ok {
		exitError(1, "unknown slot type %q", slotType)
	}

	csr, err := readCSR(*csrPath)
	if err != nil {
		exitError(1, "could not read CSR: %s", err)
	}

	notAfter, err := time.ParseDuration(*validity)
	if err != nil {
		exitError(1, "invalid validity duration: %s", err)
	}

	yk, err := piv.Open(cards[*keyID])
	if err != nil {
		exitError(1, "could not open card: %s", err)
	}

	caCert, err := yk.Certificate(slot)
	if errors.Is(err, piv.ErrNotFound) {
		exitError(1, "no certificate configured on signature slot")
	}

	caPriv, err := yk.PrivateKey(slot, caCert.PublicKey, piv.KeyAuth{
		PINPrompt: readPIN,
	})
	if errors.Is(err, piv.ErrNotFound) {
		exitError(1, "no private key configured on signature slot")
	} else if err != nil {
		exitError(1, "could not get private key: %s", err)
	}

	serial, err := randomSerial()
	if err != nil {
		exitError(1, "could not generate random serial: %s", err)
	}

	cert := &x509.Certificate{
		Version:               1,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(notAfter),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  *isCA,
		Extensions:            csr.Extensions,
		ExtraExtensions:       csr.ExtraExtensions,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
	}

	if *isCA {
		cert.KeyUsage |= x509.KeyUsageCRLSign | x509.KeyUsageCertSign
	}

	if *isServer {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	if *isClient {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, csr.PublicKey, caPriv)
	if err != nil {
		exitError(1, "could not create certificate: %s", err)
	}

	pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
}

func exitError(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(code)
}

func readCSR(path string) (*x509.CertificateRequest, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM CSR: %w", err)
	} else if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected CERTIFICATE REQUEST, got %q", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not decode CSR: %w", err)
	}

	return csr, nil
}

func readPIN() (string, error) {
	fmt.Print("PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Print("\n")

	return string(bytes.TrimSpace(pin)), nil
}

func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("could not read from random: %w", err)
	}

	return new(big.Int).SetBytes(b), nil
}

func sha1publicKey(pub crypto.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("could not marshal public key: %w", err)
	}

	sum := sha1.Sum(bytes)

	return sum[:], nil
}

func getSlot(id string) (piv.Slot, bool) {
	switch id {
	case "9a":
		return piv.SlotAuthentication, true
	case "9c":
		return piv.SlotSignature, true
	case "9e":
		return piv.SlotCardAuthentication, true
	case "9d":
		return piv.SlotKeyManagement, true
	default:
		return piv.Slot{}, false
	}
}
