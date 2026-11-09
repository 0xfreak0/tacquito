/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package secret

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/facebookincubator/tacquito/cmds/server/config"
)

const (
	// GroupEnv makes Keychain.Key the name of an environment variable whose
	// value is the pre-shared key.
	GroupEnv = "env"
	// GroupFile makes Keychain.Key a filesystem path whose contents are the
	// pre-shared key, e.g. a mounted k8s Secret or Vault agent template.
	GroupFile = "file"
)

// NewResolver returns a keychain provider that resolves pre-shared keys from
// the environment or the filesystem instead of from the config file itself.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Resolver is a keychain provider that dispatches on Keychain.Group:
//
//	group: env   -> key is an environment variable name
//	group: file  -> key is a file path
//	anything else -> key is used verbatim as the PSK, identical to Keychain.
//
// For env and file, the value holds one key per line to support PSK rotation:
// the first non-blank line is the primary (current) key and any further lines
// are older keys still accepted during the overlap window. A trailing "\r" is
// stripped from each line and blank lines are skipped; all other whitespace is
// part of the key. A rotation looks like:
//
//  1. write "new\nold"   -> devices on either key authenticate
//  2. move devices to new; watch tacquito_crypter_secret_match{index="1"}
//  3. write "new"        -> old key retired
//
// The plaintext fallback keeps existing configs working unchanged. Like the
// rest of cmds/server this is a reference implementation; production
// deployments are expected to supply a keychain provider backed by their own
// secret store.
//
// Lookups happen on every call (i.e. every new client connection), not once at
// config load. That means rotated env/file secrets are picked up without a
// config reload, and a missing secret surfaces as a failed connection for that
// scope rather than a failed config load, since the keychain provider
// interfaces give Add/AddAll no way to return an error.
type Resolver struct{}

// Add returns the func used to fetch the primary pre-shared key for a
// connection. It exists for callers that only understand a single key; see
// AddAll. The string argument passed to the returned func is the remote client
// identifier (IP for the prefix provider, hostname for dns) and is unused here.
func (r Resolver) Add(kc config.Keychain) func(context.Context, string) ([]byte, error) {
	all := r.AddAll(kc)
	return func(ctx context.Context, id string) ([]byte, error) {
		secrets, err := all(ctx, id)
		if err != nil {
			return nil, err
		}
		return secrets[0], nil
	}
}

// AddAll returns the func used to fetch every accepted pre-shared key for a
// connection, primary first. The returned slice is never empty on success.
func (Resolver) AddAll(kc config.Keychain) func(context.Context, string) ([][]byte, error) {
	switch kc.Group {
	case GroupEnv:
		return func(context.Context, string) ([][]byte, error) {
			v, ok := os.LookupEnv(kc.Key)
			if !ok {
				return nil, fmt.Errorf("keychain env var [%v] is not set", kc.Key)
			}
			keys := splitKeys([]byte(v))
			if len(keys) == 0 {
				return nil, fmt.Errorf("keychain env var [%v] is empty", kc.Key)
			}
			return keys, nil
		}
	case GroupFile:
		return func(context.Context, string) ([][]byte, error) {
			b, err := os.ReadFile(kc.Key)
			if err != nil {
				return nil, fmt.Errorf("keychain file read failed: %w", err)
			}
			keys := splitKeys(b)
			if len(keys) == 0 {
				return nil, fmt.Errorf("keychain file [%v] is empty", kc.Key)
			}
			return keys, nil
		}
	default:
		one := Keychain{}.Add(kc)
		return func(ctx context.Context, id string) ([][]byte, error) {
			k, err := one(ctx, id)
			if err != nil {
				return nil, err
			}
			return [][]byte{k}, nil
		}
	}
}

// splitKeys splits b into one key per line, stripping a trailing "\r" from
// each line and dropping blank lines.
func splitKeys(b []byte) [][]byte {
	var keys [][]byte
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 {
			keys = append(keys, line)
		}
	}
	return keys
}
