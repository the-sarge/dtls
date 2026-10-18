// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	identityTestServerName                     = "server.example"
	identityTestUnrelatedName                  = "unrelated.example"
	identityTestServerAddr    identityTestAddr = identityTestServerName + ":443"
)

type identityTestAddr string

func (a identityTestAddr) Network() string { return "test" }
func (a identityTestAddr) String() string  { return string(a) }

func identityTestCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	certificate, err := selfsign.GenerateSelfSignedWithDNS(name)
	require.NoError(t, err)
	if ip := net.ParseIP(name); ip != nil {
		template := *certificate.Leaf
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
		raw, certErr := x509.CreateCertificate(rand.Reader, &template, &template, template.PublicKey, certificate.PrivateKey)
		require.NoError(t, certErr)
		certificate.Certificate = [][]byte{raw}
		certificate.Leaf, err = x509.ParseCertificate(raw)
		require.NoError(t, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)

	return certificate, roots
}

func identityTestHandshake(t *testing.T, client, server *Conn) (error, error) {
	t.Helper()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.HandshakeContext(ctx) }()
	clientErr := client.HandshakeContext(ctx)

	return clientErr, <-serverResult
}

func TestDialVerifiesDestination(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			for _, scenario := range []struct {
				name       string
				certName   string
				serverName string
				wantError  bool
			}{
				{name: "matching IP", certName: "127.0.0.1"},
				{name: "unrelated DNS name", certName: identityTestUnrelatedName, wantError: true},
				{name: "explicit DNS name", certName: identityTestServerName, serverName: identityTestServerName},
				{name: "wrong explicit name", certName: identityTestServerName, serverName: "other.example", wantError: true},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					certificate, roots := identityTestCertificate(t, scenario.certName)
					transport, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					require.NoError(t, err)
					t.Cleanup(func() { _ = transport.Close() })
					address, ok := transport.LocalAddr().(*net.UDPAddr)
					require.True(t, ok)
					client, err := Dial("udp4", address, WithRootCAs(roots), WithServerName(scenario.serverName),
						WithMinVersion(version), WithMaxVersion(version))
					require.NoError(t, err)
					clientAddress, ok := client.LocalAddr().(*net.UDPAddr)
					require.True(t, ok)
					peerAddress := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: clientAddress.Port}
					server, err := Server(transport, peerAddress, WithCertificates(certificate),
						WithMinVersion(version), WithMaxVersion(version))
					require.NoError(t, err)
					clientErr, serverErr := identityTestHandshake(t, client, server)
					if scenario.wantError {
						var hostnameError x509.HostnameError
						require.ErrorAs(t, clientErr, &hostnameError)
						expectedName := scenario.serverName
						if expectedName == "" {
							expectedName = "127.0.0.1"
						}
						assert.Equal(t, expectedName, hostnameError.Host)

						return
					}
					require.NoError(t, clientErr)
					require.NoError(t, serverErr)
					state, ok := server.ConnectionState()
					require.True(t, ok)
					assert.Equal(t, scenario.serverName, state.ServerName, "IP literals must not be sent as SNI")
				})
			}
		})
	}
}

func TestClientVerifiesDestination(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			for _, scenario := range []struct {
				name        string
				address     net.Addr
				certName    string
				serverName  string
				insecure    bool
				wantError   bool
				missingName bool
			}{
				{name: "matching DNS", address: identityTestServerAddr, certName: identityTestServerName},
				{name: "wrong DNS", address: identityTestServerAddr, certName: identityTestUnrelatedName, wantError: true},
				{name: "matching IPv6", address: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}, certName: "::1"},
				{name: "wrong IPv6", address: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}, certName: "::2", wantError: true},
				{name: "scoped IPv6", address: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "en0", Port: 443}, certName: "fe80::1"},
				{name: "opaque address", address: identityTestAddr("opaque"), certName: identityTestServerName, wantError: true, missingName: true},
				{name: "opaque explicit identity", address: identityTestAddr("opaque"), certName: identityTestServerName, serverName: identityTestServerName},
				{name: "explicit insecure", address: identityTestAddr("opaque"), certName: identityTestServerName, insecure: true},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					certificate, roots := identityTestCertificate(t, scenario.certName)
					ca, cb := packetPipe()
					ca.remoteAddr = scenario.address
					client, err := Client(ca, ca.RemoteAddr(), WithRootCAs(roots), WithServerName(scenario.serverName),
						WithInsecureSkipVerify(scenario.insecure), WithMinVersion(version), WithMaxVersion(version))
					require.NoError(t, err)
					server, err := Server(cb, cb.RemoteAddr(), WithCertificates(certificate),
						WithMinVersion(version), WithMaxVersion(version))
					require.NoError(t, err)
					clientErr, serverErr := identityTestHandshake(t, client, server)
					if scenario.missingName {
						require.ErrorContains(t, clientErr, "server name is required")

						return
					}
					if scenario.wantError {
						var hostnameError x509.HostnameError
						require.ErrorAs(t, clientErr, &hostnameError)

						return
					}
					require.NoError(t, clientErr)
					require.NoError(t, serverErr)
				})
			}
		})
	}
}

func TestCachedSessionsVerifyDestination(t *testing.T) {
	for _, version := range []struct {
		version   protocol.Version
		suite     cryptosuite.ID
		secretLen int
	}{
		{protocol.Version1_2, cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 48},
		{protocol.Version1_3, cryptosuite.TLS_AES_128_GCM_SHA256, 32},
	} {
		t.Run(fmt.Sprintf("%x", version.version), func(t *testing.T) {
			for _, scenario := range []struct {
				name        string
				address     identityTestAddr
				cachedName  string
				wantFull    bool
				missingName bool
			}{
				{name: "matching cached identity", address: identityTestServerAddr, cachedName: identityTestServerName},
				{name: "unrelated cached identity", address: identityTestServerAddr, cachedName: identityTestUnrelatedName, wantFull: true},
				{name: "missing identity", address: "opaque", cachedName: identityTestServerName, wantFull: true, missingName: true},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					certificate, roots := identityTestCertificate(t, identityTestServerName)
					cachedCertificate, _ := identityTestCertificate(t, scenario.cachedName)
					roots.AddCert(cachedCertificate.Leaf)
					session := Session{
						Version: 1, IsClient: true, ID: []byte("cached session"), Secret: bytes.Repeat([]byte{0x42}, version.secretLen),
						CipherSuiteID: version.suite, ExtendedMasterSecret: true, PeerCertificates: cachedCertificate.Certificate,
					}
					if version.version == protocol.Version1_3 {
						serverName := identityTestServerName
						if scenario.missingName {
							serverName = ""
						}
						session.Ticket = &SessionTicket{
							CipherSuite: version.suite, CreatedAt: time.Now().Add(-time.Second), Lifetime: 60,
							ServerName: serverName, PeerCertificates: cachedCertificate.Certificate,
						}
					}
					clientStore := &earlyDataTestStore{session: session}
					session.IsClient = false
					serverStore := &earlyDataTestStore{session: session}
					ca, cb := packetPipe()
					ca.remoteAddr = scenario.address
					client, err := Client(ca, ca.RemoteAddr(), WithRootCAs(roots), WithSessionStore(clientStore),
						WithCipherSuites(version.suite), WithMinVersion(version.version), WithMaxVersion(version.version))
					require.NoError(t, err)
					server, err := Server(cb, cb.RemoteAddr(), WithCertificates(certificate), WithSessionStore(serverStore),
						WithCipherSuites(version.suite), WithMinVersion(version.version), WithMaxVersion(version.version))
					require.NoError(t, err)
					clientErr, serverErr := identityTestHandshake(t, client, server)
					if scenario.missingName {
						require.ErrorContains(t, clientErr, "server name is required")
					} else {
						require.NoError(t, clientErr)
						require.NoError(t, serverErr)
					}
					resumed := false
					switch state := client.state.(type) {
					case *dtlsstate.State12:
						resumed = state.ResumeSession != nil
					case *dtlsstate.State13:
						resumed = len(state.PSK) != 0
					}
					assert.Equal(t, !scenario.wantFull, resumed, "only matching cached identities may resume")
				})
			}
		})
	}
}
