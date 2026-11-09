/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package prefix

import (
	"context"
	"net"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopLogger struct{}

func (nopLogger) Infof(context.Context, string, ...any)                {}
func (nopLogger) Errorf(context.Context, string, ...any)               {}
func (nopLogger) Debugf(context.Context, string, ...any)               {}
func (nopLogger) Record(context.Context, map[string]string, ...string) {}

var (
	handler = tq.HandlerFunc(func(tq.Response, tq.Request) {})
	sc      = config.SecretConfig{Name: "test", Options: map[string]string{"prefixes": `["192.0.2.0/24"]`}}
	inside  = &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1}
	outside = &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1}
)

func TestNewMultiGetSecrets(t *testing.T) {
	var gotID string
	all := func(_ context.Context, id string) ([][]byte, error) {
		gotID = id
		return [][]byte{[]byte("new"), []byte("old")}, nil
	}
	sp := New(nopLogger{}).NewMulti(context.Background(), sc, handler, all)
	require.NotNil(t, sp)
	msp, ok := sp.(tq.MultiSecretProvider)
	require.True(t, ok, "NewMulti must return a tq.MultiSecretProvider")

	secrets, h, err := msp.GetSecrets(context.Background(), inside)
	require.NoError(t, err)
	assert.NotNil(t, h)
	assert.Equal(t, [][]byte{[]byte("new"), []byte("old")}, secrets)
	assert.Equal(t, "192.0.2.10", gotID, "keychain func receives the remote IP")

	// Get stays single-key and returns the primary
	secret, _, err := msp.Get(context.Background(), inside)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), secret)

	_, _, err = msp.GetSecrets(context.Background(), outside)
	assert.Error(t, err)
}

// TestNewSingleKeyGetSecrets ensures providers built with the original New
// path also satisfy GetSecrets with their one key.
func TestNewSingleKeyGetSecrets(t *testing.T) {
	one := func(context.Context, string) ([]byte, error) { return []byte("only"), nil }
	sp := New(nopLogger{}).New(context.Background(), sc, handler, one)
	require.NotNil(t, sp)
	secrets, _, err := sp.(tq.MultiSecretProvider).GetSecrets(context.Background(), inside)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("only")}, secrets)
}
