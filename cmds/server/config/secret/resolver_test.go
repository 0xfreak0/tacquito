/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package secret

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/facebookincubator/tacquito/cmds/server/config"
)

func TestResolver(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("TQ_TEST_PSK", "envsecret")
	t.Setenv("TQ_TEST_EMPTY", "")

	tests := []struct {
		name    string
		kc      config.Keychain
		want    string
		wantErr bool
	}{
		{name: "env var", kc: config.Keychain{Group: GroupEnv, Key: "TQ_TEST_PSK"}, want: "envsecret"},
		{name: "env var unset", kc: config.Keychain{Group: GroupEnv, Key: "TQ_TEST_DOES_NOT_EXIST"}, wantErr: true},
		{name: "env var empty", kc: config.Keychain{Group: GroupEnv, Key: "TQ_TEST_EMPTY"}, wantErr: true},
		{name: "file", kc: config.Keychain{Group: GroupFile, Key: write("psk", "filesecret")}, want: "filesecret"},
		{name: "file trailing newline trimmed", kc: config.Keychain{Group: GroupFile, Key: write("psk_nl", "filesecret\r\n")}, want: "filesecret"},
		{name: "file inner whitespace kept", kc: config.Keychain{Group: GroupFile, Key: write("psk_ws", " a b \n")}, want: " a b "},
		{name: "file missing", kc: config.Keychain{Group: GroupFile, Key: filepath.Join(dir, "nope")}, wantErr: true},
		{name: "file empty", kc: config.Keychain{Group: GroupFile, Key: write("empty", "\n")}, wantErr: true},
		{name: "other group falls back to plaintext", kc: config.Keychain{Group: "tacquito", Key: "fooman"}, want: "fooman"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewResolver().Add(tc.kc)(context.Background(), "192.0.2.1")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got secret %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolverFileRotation verifies the file is read per call, so a rotated
// secret (e.g. an updated k8s Secret volume) is picked up without a reload.
func TestResolverFileRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	get := NewResolver().Add(config.Keychain{Group: GroupFile, Key: p})
	if got, _ := get(context.Background(), ""); string(got) != "one" {
		t.Fatalf("got %q, want one", got)
	}
	if err := os.WriteFile(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(context.Background(), ""); string(got) != "two" {
		t.Fatalf("got %q, want two", got)
	}
}
