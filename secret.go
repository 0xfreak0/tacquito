/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"context"
	"fmt"
	"net"
	"slices"
)

// SecretProvider is responsible for secret selection for incoming client connections
// It provides configuration items for the server to process any connections that originate
// on a given net.Conn.  Only the RemoteAddr is provided to make this determination.
type SecretProvider interface {
	Get(ctx context.Context, remote net.Addr) ([]byte, Handler, error)
}

// MultiSecretProvider is an optional extension of SecretProvider for
// pre-shared key rotation. When the SecretProvider given to NewServer also
// implements it, GetSecrets is used instead of Get and the connection accepts
// any of the returned keys.
//
// Order matters: secrets[0] is the primary (current) key. Candidates are tried
// in order on the first obfuscated packet of a connection and the first key
// that de-obfuscates it into a parseable body is used for the rest of that
// connection, including replies. If none match, the connection is handled
// exactly as a single-key bad secret, using secrets[0] for the reply.
//
// Key selection relies on the same heuristic as bad secret detection (see
// isBadSecret), so every extra key slightly raises the odds of a wrong key
// being accepted for a connection. Return two keys during a rotation window,
// not a long history. The tacquito_crypter_secret_match metric reports which
// index connections selected, so you know when the old key is unused.
//
// TLS connections ignore all of this, as they do the single secret.
type MultiSecretProvider interface {
	SecretProvider
	GetSecrets(ctx context.Context, remote net.Addr) ([][]byte, Handler, error)
}

// getSecrets fetches the candidate keys for remote from sp, using
// MultiSecretProvider when implemented. nil keys are dropped; it is an error
// for no keys to remain or for the handler to be nil.
func getSecrets(ctx context.Context, sp SecretProvider, remote net.Addr) ([][]byte, Handler, error) {
	var secrets [][]byte
	var handler Handler
	var err error
	if msp, ok := sp.(MultiSecretProvider); ok {
		secrets, handler, err = msp.GetSecrets(ctx, remote)
	} else {
		var secret []byte
		secret, handler, err = sp.Get(ctx, remote)
		secrets = [][]byte{secret}
	}
	if err != nil {
		return nil, nil, err
	}
	secrets = slices.DeleteFunc(secrets, func(s []byte) bool { return s == nil })
	if len(secrets) == 0 || handler == nil {
		return nil, nil, fmt.Errorf("secret provider returned no secret or handler for [%v]", remote)
	}
	return secrets, handler, nil
}

// SingleSecret adapts a single-key secret func to the multi-key form used by
// MultiSecretProvider implementations. A nil key is returned as no keys.
func SingleSecret(f func(context.Context, string) ([]byte, error)) func(context.Context, string) ([][]byte, error) {
	return func(ctx context.Context, id string) ([][]byte, error) {
		k, err := f(ctx, id)
		if err != nil || k == nil {
			return nil, err
		}
		return [][]byte{k}, nil
	}
}

// PrimarySecret adapts a GetSecrets result to the single-key Get form by
// returning the primary key, secrets[0]. It lets MultiSecretProvider
// implementations write Get as: return PrimarySecret(p.GetSecrets(ctx, remote))
func PrimarySecret(secrets [][]byte, h Handler, err error) ([]byte, Handler, error) {
	if err != nil {
		return nil, nil, err
	}
	if len(secrets) == 0 {
		return nil, h, nil
	}
	return secrets[0], h, nil
}
