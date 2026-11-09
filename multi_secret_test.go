/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	oldKey   = []byte("fooman")
	newKey   = []byte("new-rotated-key")
	wrongKey = []byte("not-configured")
)

// authenStart returns a plaintext PAP AuthenStart packet.
func authenStart(t *testing.T, sessionID SessionID, flags ...HeaderFlag) *Packet {
	t.Helper()
	body, err := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypePAP),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("tty0"),
		SetAuthenStartRemAddr("192.0.2.1"),
		SetAuthenStartData(AuthenData("password")),
	).MarshalBinary()
	require.NoError(t, err)
	hopts := []HeaderOption{
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSeqNo(1),
		SetHeaderSessionID(sessionID),
	}
	for _, f := range flags {
		hopts = append(hopts, SetHeaderFlag(f))
	}
	p := NewPacket(SetPacketHeader(NewHeader(hopts...)), SetPacketBody(body))
	p.Header.Length = uint32(len(p.Body))
	return p
}

// encryptedAuthenStart returns a wire-format AuthenStart packet obfuscated
// with secret. Distinct session IDs let callers build several packets for one
// connection.
func encryptedAuthenStart(t *testing.T, secret []byte, sessionID SessionID, flags ...HeaderFlag) []byte {
	t.Helper()
	p := authenStart(t, sessionID, flags...)
	require.NoError(t, crypt(secret, p))
	b, err := p.MarshalBinary()
	require.NoError(t, err)
	return b
}

func multiCrypterFor(data []byte, secrets ...[]byte) (*crypter, *mockConnection) {
	conn := &mockConnection{data: data}
	c := newMultiCrypter(secrets, conn, false, false)
	// tests feed bytes through mockConnection directly; mirror newCrypter's reader
	c.Reader = bufio.NewReader(conn)
	return c, conn
}

func TestMultiCrypterSelectsMatchingKey(t *testing.T) {
	tests := []struct {
		name    string
		sentKey []byte
		keys    [][]byte
		want    int
	}{
		{name: "primary key", sentKey: newKey, keys: [][]byte{newKey, oldKey}, want: 0},
		{name: "secondary key", sentKey: oldKey, keys: [][]byte{newKey, oldKey}, want: 1},
		{name: "third key", sentKey: oldKey, keys: [][]byte{newKey, wrongKey, oldKey}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(crypterSecretMatch.WithLabelValues(secretIndexLabel(tc.want)))
			c, _ := multiCrypterFor(encryptedAuthenStart(t, tc.sentKey, 1), tc.keys...)
			p, err := c.read()
			require.NoError(t, err)

			var as AuthenStart
			require.NoError(t, Unmarshal(p.Body, &as))
			assert.Equal(t, AuthenUser("admin"), as.User)
			assert.Equal(t, tc.want, c.matched)
			assert.Equal(t, tc.sentKey, c.secret, "crypter must lock to the matched key")
			assert.Equal(t, before+1, testutil.ToFloat64(crypterSecretMatch.WithLabelValues(secretIndexLabel(tc.want))))
		})
	}
}

// TestMultiCrypterRepliesWithMatchedKey ensures the reply is obfuscated with
// the key the client used, not the primary key.
func TestMultiCrypterRepliesWithMatchedKey(t *testing.T) {
	c, conn := multiCrypterFor(encryptedAuthenStart(t, oldKey, 7), newKey, oldKey)
	req, err := c.read()
	require.NoError(t, err)

	body, err := NewAuthenReply(SetAuthenReplyStatus(AuthenStatusPass)).MarshalBinary()
	require.NoError(t, err)
	reply := NewPacket(SetPacketHeader(NewHeader(
		SetHeaderVersion(req.Header.Version),
		SetHeaderType(Authenticate),
		SetHeaderSeqNo(2),
		SetHeaderSessionID(req.Header.SessionID),
	)), SetPacketBody(body))
	_, err = c.write(reply)
	require.NoError(t, err)

	// a client holding only the old key must be able to read the reply
	client := &crypter{secret: oldKey, Conn: conn, Reader: bufio.NewReader(conn)}
	got, err := client.read()
	require.NoError(t, err)
	var ar AuthenReply
	require.NoError(t, Unmarshal(got.Body, &ar))
	assert.Equal(t, AuthenStatusPass, ar.Status)
}

// TestMultiCrypterLocksPerConnection ensures the key chosen on the first
// packet is kept: later packets on the connection are not re-negotiated.
func TestMultiCrypterLocksPerConnection(t *testing.T) {
	data := append(encryptedAuthenStart(t, oldKey, 1), encryptedAuthenStart(t, oldKey, 2)...)
	c, _ := multiCrypterFor(data, newKey, oldKey)
	for range 2 {
		_, err := c.read()
		require.NoError(t, err)
	}
	assert.Equal(t, 1, c.matched)

	// once locked to the old key, a packet under the new key is a bad secret
	data = append(encryptedAuthenStart(t, oldKey, 1), encryptedAuthenStart(t, newKey, 2)...)
	c, _ = multiCrypterFor(data, newKey, oldKey)
	_, err := c.read()
	require.NoError(t, err)
	_, err = c.read()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad secret detected")
}

// TestMultiCrypterNoMatch ensures behavior matches the single-key path when no
// candidate works: bad secret error, reply obfuscated with the primary key,
// and the bad secret metric counted exactly once.
func TestMultiCrypterNoMatch(t *testing.T) {
	before := testutil.ToFloat64(crypterBadSecret)
	c, conn := multiCrypterFor(encryptedAuthenStart(t, wrongKey, 1), newKey, oldKey)
	_, err := c.read()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad secret detected")
	assert.Equal(t, -1, c.matched)
	assert.Equal(t, before+1, testutil.ToFloat64(crypterBadSecret))

	client := &crypter{secret: newKey, Conn: conn, Reader: bufio.NewReader(conn)}
	got, err := client.read()
	require.NoError(t, err, "bad secret reply should be obfuscated with the primary key")
	var ar AuthenReply
	require.NoError(t, Unmarshal(got.Body, &ar))
	assert.Equal(t, AuthenStatusError, ar.Status)
}

// TestMultiCrypterUnencryptedDoesNotLock ensures a packet with the unencrypted
// flag (non-TLS) doesn't pick a key, since every key trivially "matches" it.
func TestMultiCrypterUnencryptedDoesNotLock(t *testing.T) {
	data := append(encryptedAuthenStart(t, nil, 1, UnencryptedFlag), encryptedAuthenStart(t, oldKey, 2)...)
	c, _ := multiCrypterFor(data, newKey, oldKey)
	_, err := c.read()
	require.NoError(t, err)
	assert.Equal(t, -1, c.matched)
	_, err = c.read()
	require.NoError(t, err)
	assert.Equal(t, 1, c.matched)
}

func TestNewCrypterSingleKeyUnchanged(t *testing.T) {
	c := newCrypter(oldKey, &mockConnection{}, false, false)
	assert.Equal(t, oldKey, c.secret)
	assert.Nil(t, c.candidates)
	assert.Equal(t, -1, c.matched)
}

// multiProvider is a MultiSecretProvider test double.
type multiProvider struct {
	secrets [][]byte
	handler Handler
}

func (m multiProvider) Get(ctx context.Context, remote net.Addr) ([]byte, Handler, error) {
	return m.secrets[0], m.handler, nil
}

func (m multiProvider) GetSecrets(ctx context.Context, remote net.Addr) ([][]byte, Handler, error) {
	return m.secrets, m.handler, nil
}

// singleProvider only implements the original SecretProvider interface.
type singleProvider struct {
	secret  []byte
	handler Handler
}

func (s singleProvider) Get(ctx context.Context, remote net.Addr) ([]byte, Handler, error) {
	return s.secret, s.handler, nil
}

type nopLogger struct{}

func (nopLogger) Infof(context.Context, string, ...any)                {}
func (nopLogger) Errorf(context.Context, string, ...any)               {}
func (nopLogger) Debugf(context.Context, string, ...any)               {}
func (nopLogger) Record(context.Context, map[string]string, ...string) {}

var passHandler = HandlerFunc(func(resp Response, req Request) {
	resp.Reply(NewAuthenReply(SetAuthenReplyStatus(AuthenStatusPass)))
})

// startServer runs a real Server on loopback and returns its address.
func startServer(t *testing.T, sp SecretProvider) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := NewServer(nopLogger{}, sp)
	done := make(chan struct{})
	go func() { s.Serve(ctx, l.(*net.TCPListener)); close(done) }()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	})
	return l.Addr().String()
}

func authenPAP(t *testing.T, addr string, secret []byte) (*AuthenReply, error) {
	t.Helper()
	c, err := NewClient(SetClientDialer("tcp", addr, secret))
	require.NoError(t, err)
	defer c.Close()
	// client.write obfuscates with the client's secret
	resp, err := c.Send(authenStart(t, 99))
	if err != nil {
		return nil, err
	}
	var ar AuthenReply
	if err := Unmarshal(resp.Body, &ar); err != nil {
		return nil, err
	}
	return &ar, nil
}

// TestServerMultiSecretRotation is the end-to-end rotation scenario: during
// the overlap window, devices on either key authenticate; others do not.
func TestServerMultiSecretRotation(t *testing.T) {
	addr := startServer(t, multiProvider{secrets: [][]byte{newKey, oldKey}, handler: passHandler})
	for _, key := range [][]byte{newKey, oldKey} {
		ar, err := authenPAP(t, addr, key)
		require.NoError(t, err, "key %q", key)
		assert.Equal(t, AuthenStatusPass, ar.Status)
	}
	_, err := authenPAP(t, addr, wrongKey)
	assert.Error(t, err)
}

// TestServerSingleSecretProviderUnchanged ensures providers that only
// implement SecretProvider keep working, and only accept their one key.
func TestServerSingleSecretProviderUnchanged(t *testing.T) {
	addr := startServer(t, singleProvider{secret: oldKey, handler: passHandler})
	ar, err := authenPAP(t, addr, oldKey)
	require.NoError(t, err)
	assert.Equal(t, AuthenStatusPass, ar.Status)
	_, err = authenPAP(t, addr, newKey)
	assert.Error(t, err)
}
