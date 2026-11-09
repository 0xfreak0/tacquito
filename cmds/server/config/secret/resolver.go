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
// The plaintext fallback keeps existing configs working unchanged. Like the
// rest of cmds/server this is a reference implementation; production
// deployments are expected to supply a keychain provider backed by their own
// secret store.
//
// Lookups happen on every call (i.e. every new client connection), not once at
// config load. That means rotated env/file secrets are picked up without a
// config reload, and a missing secret surfaces as a failed connection for that
// scope rather than a failed config load, since the keychainProvider interface
// gives Add no way to return an error.
type Resolver struct{}

// Add returns the func used to fetch the pre-shared key for a connection. The
// string argument passed to the returned func is the remote client identifier
// (IP for the prefix provider, hostname for dns) and is unused here.
func (Resolver) Add(kc config.Keychain) func(context.Context, string) ([]byte, error) {
	switch kc.Group {
	case GroupEnv:
		return func(context.Context, string) ([]byte, error) {
			v, ok := os.LookupEnv(kc.Key)
			if !ok {
				return nil, fmt.Errorf("keychain env var [%v] is not set", kc.Key)
			}
			if v == "" {
				return nil, fmt.Errorf("keychain env var [%v] is empty", kc.Key)
			}
			return []byte(v), nil
		}
	case GroupFile:
		return func(context.Context, string) ([]byte, error) {
			b, err := os.ReadFile(kc.Key)
			if err != nil {
				return nil, fmt.Errorf("keychain file read failed: %w", err)
			}
			// Trim only the trailing line ending that `echo` and most editors
			// add; other whitespace may legitimately be part of the key.
			b = bytes.TrimRight(b, "\r\n")
			if len(b) == 0 {
				return nil, fmt.Errorf("keychain file [%v] is empty", kc.Key)
			}
			return b, nil
		}
	default:
		return Keychain{}.Add(kc)
	}
}
