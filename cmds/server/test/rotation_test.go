/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config/secret"
	"github.com/facebookincubator/tacquito/cmds/server/loader"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPSKRotation exercises rotation through the full example-server stack:
// yaml config -> loader -> secret.Resolver (file) -> prefix provider -> server.
func TestPSKRotation(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "psk")
	require.NoError(t, os.WriteFile(keyFile, []byte("newkey\nfooman\n"), 0o600))

	cfg := strings.Replace(SampleConfig, "      group: tacquito\n      key: fooman\n",
		"      group: file\n      key: "+keyFile+"\n", 1)
	require.NotEqual(t, SampleConfig, cfg, "sample config secret block changed; update this test")
	cfgPath := filepath.Join(dir, "tacquito.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	logger := log.New(10, os.Stderr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sp, err := MockSecretProvider(ctx, logger, cfgPath, loader.SetKeychainProvider(secret.NewResolver()))
	require.NoError(t, err)
	_, ok := sp.(tq.MultiSecretProvider)
	require.True(t, ok, "loader must expose multiple keys to the server")

	listener, err := net.Listen("tcp6", "[::1]:0")
	require.NoError(t, err)
	go tq.NewServer(logger, sp).Serve(ctx, listener.(*net.TCPListener))

	login := func(key string) error {
		test := PapLoginFlow()
		c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), []byte(key)))
		require.NoError(t, err)
		defer c.Close()
		for _, s := range test.Seq {
			resp, err := c.Send(s.Packet)
			if err != nil {
				return err
			}
			if err := s.ValidateBody(resp.Body); err != nil {
				return err
			}
		}
		return nil
	}

	// overlap window: both keys work, anything else does not
	assert.NoError(t, login("newkey"), "primary key")
	assert.NoError(t, login("fooman"), "old key during overlap")
	assert.Error(t, login("wrong"), "unconfigured key")

	// retire the old key by editing the file; no config reload needed since
	// the keychain is resolved per connection
	require.NoError(t, os.WriteFile(keyFile, []byte("newkey\n"), 0o600))
	assert.NoError(t, login("newkey"), "primary key after retiring old")
	assert.Error(t, login("fooman"), "old key after retirement")
}
