// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/YurilLAB/coraza/carnical/formats"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

type setupOutputFault struct{ io.Writer }

func (w setupOutputFault) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("No account configuration directory is available.")) {
		return 0, io.ErrClosedPipe
	}
	return w.Writer.Write(p)
}

// This is executable startup and TCP forwarding behavior, which cannot be expressed as an engine profile.
func TestRequestFormatsAtCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "carnical")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	t.Run("site configuration parser", func(t *testing.T) {
		tests := []struct {
			name, data string
			bad        bool
		}{
			{name: "empty settings", data: "{\"version\":1,\"flags\":{}}", bad: false},
			{name: "boolean string option", data: "{\"version\":1,\"flags\":{\"upstream\":true}}", bad: true},
			{name: "all flag kinds", data: "{\"version\":1,\"flags\":{\"upstream\":\"http://example.test\",\"local-rules\":false,\"max-body\":2048,\"max-upstream\":2,\"ddos-rate\":0.5,\"eval-budget\":\"500ms\"}}", bad: false},
			{name: "unknown field", data: "{\"version\":1,\"flags\":{},\"other\":1}", bad: true},
			{name: "wrong version", data: "{\"version\":2,\"flags\":{}}", bad: true},
			{name: "null root", data: "null", bad: true},
			{name: "array root", data: "[]", bad: true},
			{name: "null flags", data: "{\"version\":1,\"flags\":null}", bad: true},
			{name: "missing version", data: "{\"flags\":{}}", bad: true},
			{name: "missing flags", data: "{\"version\":1}", bad: true},
			{name: "duplicate root field", data: "{\"version\":1,\"version\":1,\"flags\":{}}", bad: true},
			{name: "escaped duplicate flag", data: "{\"version\":1,\"flags\":{\"mode\":\"block\",\"\\u006dode\":\"off\"}}", bad: true},
			{name: "duplicate flags object", data: "{\"version\":1,\"flags\":{},\"flags\":{}}", bad: true},
			{name: "null flag", data: "{\"version\":1,\"flags\":{\"mode\":null}}", bad: true},
			{name: "unknown flag", data: "{\"version\":1,\"flags\":{\"mod\":\"block\"}}", bad: true},
			{name: "case alias", data: "{\"version\":1,\"flags\":{\"MODE\":\"block\"}}", bad: true},
			{name: "nested string", data: "{\"version\":1,\"flags\":{\"mode\":{\"value\":\"block\"}}}", bad: true},
			{name: "string boolean", data: "{\"version\":1,\"flags\":{\"local-rules\":\"false\"}}", bad: true},
			{name: "number boolean", data: "{\"version\":1,\"flags\":{\"local-rules\":0}}", bad: true},
			{name: "string integer", data: "{\"version\":1,\"flags\":{\"max-body\":\"2048\"}}", bad: true},
			{name: "fractional integer", data: "{\"version\":1,\"flags\":{\"max-body\":1.5}}", bad: true},
			{name: "integer overflow", data: "{\"version\":1,\"flags\":{\"max-body\":9223372036854775808}}", bad: true},
			{name: "float overflow", data: "{\"version\":1,\"flags\":{\"ddos-rate\":1e999}}", bad: true},
			{name: "invalid duration", data: "{\"version\":1,\"flags\":{\"eval-budget\":\"later\"}}", bad: true},
			{name: "numeric duration", data: "{\"version\":1,\"flags\":{\"eval-budget\":2}}", bad: true},
			{name: "recursive config", data: "{\"version\":1,\"flags\":{\"config\":\"next.json\"}}", bad: true},
			{name: "file check action", data: "{\"version\":1,\"flags\":{\"check\":true}}", bad: true},
			{name: "file network action", data: "{\"version\":1,\"flags\":{\"check-origin\":true}}", bad: true},
			{name: "file HTTP action", data: `{"version":1,"flags":{"check-origin-http":true}}`, bad: true},
			{name: "file probe action", data: `{"version":1,"flags":{"probe":"ready"}}`, bad: true},
			{name: "file version action", data: "{\"version\":1,\"flags\":{\"version\":true}}", bad: true},
			{name: "key bootstrap in site file", data: `{"version":1,"flags":{"config-key-file":"other.key"}}`, bad: true},
			{name: "null private section", data: `{"version":1,"flags":{},"private":null}`, bad: true},
			{name: "duplicate encrypted field", data: `{"version":1,"flags":{},"private":{"key-id":"abc","key-id":"abc","sealed":"abc"}}`, bad: true},
			{name: "unknown encrypted field", data: `{"version":1,"flags":{},"private":{"key-id":"abc","sealed":"abc","extra":1}}`, bad: true},
			{name: "missing encrypted payload", data: `{"version":1,"flags":{},"private":{"key-id":"abc"}}`, bad: true},
			{name: "trailing document", data: "{\"version\":1,\"flags\":{}} {}", bad: true},
			{name: "truncated document", data: "{\"version\":1,\"flags\":{\"mode\":\"block\"}", bad: true},
			{name: "invalid UTF8", data: "{\"version\":1,\"flags\":{\"mode\":\"" + string([]byte{0xff}) + "\"}}", bad: true},
			{name: "over size limit", data: "{\"version\":1,\"flags\":{}}" + strings.Repeat(" ", maxSiteConfigBytes), bad: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				flags := flag.NewFlagSet("site", flag.ContinueOnError)
				upstream := flags.String("upstream", "", "")
				flags.String("mode", "detect", "")
				localRules := flags.Bool("local-rules", true, "")
				flags.Int64("max-body", 1<<20, "")
				flags.Int("max-upstream", 256, "")
				flags.Float64("ddos-rate", 50, "")
				flags.Duration("eval-budget", time.Second, "")
				flags.String("config", "", "")
				flags.Bool("check", false, "")
				flags.Bool("check-origin", false, "")
				flags.Bool("check-origin-http", false, "")
				flags.Bool("version", false, "")
				flags.String("probe", "", "")
				if err := flags.Parse([]string{"-upstream", "http://override.test", "-local-rules=false"}); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
					t.Fatal(err)
				}
				_, err := loadSiteConfig(path, flags)
				if (err != nil) != tc.bad {
					t.Fatalf("error %v, want invalid=%v", err, tc.bad)
				}
				if !tc.bad && (*upstream != "http://override.test" || *localRules) {
					t.Fatal("file replaced explicit CLI settings")
				}
			})
		}
		t.Run("symlink file", func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "site.json")
			if err := os.WriteFile(path, []byte(`{"version":1,"flags":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link.json")
			if err := os.Symlink(path, link); err != nil {
				if runtime.GOOS == "windows" {
					t.Skip("Windows symlink creation requires host privilege")
				}
				t.Fatal(err)
			}
			if _, err := loadSiteConfig(link, flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("symlink accepted as configuration")
			}
		})
		t.Run("nonregular file", func(t *testing.T) {
			if _, err := loadSiteConfig(t.TempDir(), flag.NewFlagSet("site", flag.ContinueOnError)); err == nil {
				t.Fatal("directory accepted as config")
			}
		})
	})

	t.Run("setup wizard and encrypted runtime", func(t *testing.T) {
		var reached atomic.Int64
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Add(1)
			if r.Host != "example.test" {
				t.Errorf("unexpected origin Host %q", r.Host)
			}
			w.WriteHeader(200)
		}))
		defer origin.Close()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listen := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, prefix                                                               string
			save, bad, exists, defaultKey, sameKey, noProfile, missingKey, outputError bool
		}{
			{name: "declined save"},
			{name: "encrypted saved site", save: true},
			{name: "default account key store", save: true, defaultKey: true},
			{name: "explicit key without account directory", save: true, noProfile: true},
			{name: "missing account directory needs a key path", save: true, bad: true, noProfile: true, missingKey: true},
			{name: "key fallback output failure saves nothing", save: true, bad: true, noProfile: true, outputError: true},
			{name: "EOF before consent", prefix: "example.test\n", bad: true},
			{name: "control character", prefix: "example.test\x1b\n", bad: true},
			{name: "oversized input", prefix: strings.Repeat("x", 4097) + "\n", bad: true},
			{name: "credentials refused", prefix: "example.test\nhttp://admin:password@127.0.0.1\n", bad: true},
			{name: "public plaintext listener refused", prefix: "example.test\n" + origin.URL + "\ny\n\n\nlocal\n0.0.0.0:8080\n", bad: true},
			{name: "existing config preserved", save: true, exists: true, bad: true},
			{name: "key and config need separate files", save: true, sameKey: true, bad: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				configPath, keyPath := filepath.Join(dir, "site.json"), filepath.Join(dir, "key.bin")
				keyAnswer := keyPath
				if tc.sameKey {
					keyAnswer = configPath
				}
				if tc.defaultKey {
					t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
					t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
					keyAnswer = ""
				}
				if tc.noProfile {
					t.Setenv("APPDATA", "")
					t.Setenv("XDG_CONFIG_HOME", "")
					t.Setenv("HOME", "")
				}
				if tc.missingKey {
					keyAnswer = ""
				}
				if tc.exists {
					if err := os.WriteFile(configPath, []byte("original"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				answer := "n"
				if tc.save {
					answer = "YES"
				}
				input := tc.prefix
				if input == "" {
					input = strings.Join([]string{"example.test", origin.URL, "y", "", "", "local", listen, "block", "n", "n", answer, configPath, keyAnswer, ""}, "\n")
				}
				var output bytes.Buffer
				var err error
				if tc.save && !tc.bad {
					setupCmd := exec.Command(bin, "setup")
					setupCmd.Stdin = strings.NewReader(input)
					setupCmd.Stdout, setupCmd.Stderr = &output, &output
					err = setupCmd.Run()
				} else {
					var sink io.Writer = &output
					if tc.outputError {
						sink = setupOutputFault{Writer: &output}
					}
					err = runSetup(strings.NewReader(input), sink, runArgs)
				}
				if tc.outputError && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("fallback output failure was not returned: %v", err)
				}
				if (err != nil) != tc.bad {
					t.Fatalf("wizard error=%v, want bad=%v; %s", err, tc.bad, &output)
				}
				if !tc.save || tc.bad {
					if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
						t.Fatal("key written without successful save")
					}
					data, err := os.ReadFile(configPath)
					if tc.exists {
						if err != nil || string(data) != "original" {
							t.Fatal("existing config changed")
						}
					} else if !os.IsNotExist(err) {
						t.Fatal("config written without consent")
					}
					return
				}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte(origin.URL)) || bytes.Contains(data, []byte("127.0.0.1/32")) || bytes.Contains(data, []byte(keyPath)) {
					t.Fatal("private origin details or key path stored in clear")
				}
				var document siteDocument
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				if document.Private == nil || document.Flags["mode"] != "block" {
					t.Fatal("missing ciphertext or reviewable policy")
				}
				if tc.defaultKey {
					keyPath, err = siteKeyPath(document.Private.KeyID)
					if err != nil {
						t.Fatal(err)
					}
				}
				key, err := readSiteFile(keyPath, 32, true)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key)
				baseArgs := []string{"-config", configPath}
				if !tc.defaultKey {
					baseArgs = append(baseArgs, "-config-key-file", keyPath)
				}
				if err := runArgs(append(append([]string{}, baseArgs...), "-check")); err != nil {
					t.Fatal(err)
				}
				flags := flag.NewFlagSet("encrypted override", flag.ContinueOnError)
				for _, name := range []string{"hosts", "listen", "mode", "formats-mode", "upstream", "upstream-host", "origin-allow", "config-key-file"} {
					flags.String(name, "", "")
				}
				flags.Bool("wordpress", false, "")
				if err := flags.Parse([]string{"-upstream=http://override.test", "-config-key-file=" + keyPath}); err != nil {
					t.Fatal(err)
				}
				if _, err := loadSiteConfig(configPath, flags); err != nil {
					t.Fatal(err)
				}
				if flags.Lookup("upstream").Value.String() != "http://override.test" {
					t.Fatal("encrypted file replaced explicit CLI origin")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, baseArgs...)
				var log bytes.Buffer
				cmd.Stderr = &log
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := cmd.Process.Kill(); err != nil && ctx.Err() == nil {
						t.Error(err)
					}
					_ = cmd.Wait() // deliberate test teardown of the live child
					if strings.Contains(log.String(), origin.URL) {
						t.Error("private origin URL disclosed in default startup log")
					}
				}()
				client := &http.Client{Timeout: time.Second}
				send := func(method, path, body string) (int, error) {
					request, err := http.NewRequest(method, "http://"+listen+path, strings.NewReader(body))
					if err != nil {
						return 0, err
					}
					request.Host = "example.test"
					if body != "" {
						request.Header.Set("Content-Type", "application/json")
					}
					response, err := client.Do(request)
					if err != nil {
						return 0, err
					}
					_, readErr := io.Copy(io.Discard, response.Body)
					closeErr := response.Body.Close()
					if readErr != nil {
						return 0, readErr
					}
					return response.StatusCode, closeErr
				}
				ready := false
				for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
					if status, err := send("GET", "/", ""); err == nil && status == 200 {
						ready = true
						break
					}
					time.Sleep(30 * time.Millisecond)
				}
				if !ready {
					t.Fatal("encrypted WAF did not become ready")
				}
				before := reached.Load()
				for _, attack := range []struct {
					method, path, body string
					status             int
				}{
					{"POST", "/api", `{"id":1,"id":2}`, 400},
					{"GET", "/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "", 403},
				} {
					status, err := send(attack.method, attack.path, attack.body)
					if err != nil || status != attack.status {
						t.Fatalf("live refusal: status=%d err=%v", status, err)
					}
				}
				if reached.Load() != before {
					t.Fatal("refused request reached origin")
				}
				for _, mutation := range []struct {
					name   string
					mutate func(*siteDocument)
				}{
					{"ciphertext tamper", func(d *siteDocument) {
						sealed, _ := base64.StdEncoding.DecodeString(d.Private.Sealed)
						sealed[len(sealed)-1] ^= 1
						d.Private.Sealed = base64.StdEncoding.EncodeToString(sealed)
					}},
					{"key ID binding", func(d *siteDocument) { d.Private.KeyID = strings.Repeat("0", 32) }},
					{"path traversal key ID", func(d *siteDocument) { d.Private.KeyID = "../../key" }},
					{"duplicate across sections", func(d *siteDocument) { d.Flags["upstream"] = origin.URL }},
					{"encrypted action", func(d *siteDocument) {
						d.Private, err = sealSiteSettings(map[string]any{"check": true}, d.Private.KeyID, key)
						if err != nil {
							t.Fatal(err)
						}
					}},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						var changed siteDocument
						if err := json.Unmarshal(data, &changed); err != nil {
							t.Fatal(err)
						}
						mutation.mutate(&changed)
						encoded, err := json.Marshal(changed)
						if err != nil {
							t.Fatal(err)
						}
						badPath := filepath.Join(t.TempDir(), "bad.json")
						if err := os.WriteFile(badPath, encoded, 0600); err != nil {
							t.Fatal(err)
						}
						if err := runArgs([]string{"-config", badPath, "-config-key-file", keyPath, "-check"}); err == nil {
							t.Fatal("invalid encrypted config accepted")
						}
					})
				}
				t.Run("wrong key", func(t *testing.T) {
					wrongPath := filepath.Join(t.TempDir(), "wrong.key")
					wrong := make([]byte, 32)
					if _, err := cryptorand.Read(wrong); err != nil {
						t.Fatal(err)
					}
					if err := writeNewSiteFile(wrongPath, wrong); err != nil {
						t.Fatal(err)
					}
					if err := runArgs([]string{"-config", configPath, "-config-key-file", wrongPath, "-check"}); err == nil {
						t.Fatal("wrong key accepted")
					}
				})
				t.Run("key permissions", func(t *testing.T) {
					if runtime.GOOS == "windows" {
						if out, err := exec.Command("icacls", keyPath, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
							t.Fatalf("ACL fixture: %v %s", err, out)
						}
					} else if err := os.Chmod(keyPath, 0644); err != nil {
						t.Fatal(err)
					}
					if err := runArgs(append(append([]string{}, baseArgs...), "-check")); err == nil {
						t.Fatal("shared-readable key accepted")
					}
				})
			})
		}
	})

	t.Run("new site file starts private", func(t *testing.T) {
		fixture := t.TempDir()
		dir := filepath.Join(fixture, "root")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)(R)").CombinedOutput(); err != nil {
				t.Fatalf("shared-directory fixture: %v %s", err, out)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		file, err := createSiteFile(root, "key.bin")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		// Check immediately after creation, before any later ACL change or write.
		if err := checkPrivateSiteFile(file); err != nil {
			t.Fatalf("new file permits inherited access before protection: %v", err)
		}
		if runtime.GOOS == "windows" {
			for _, name := range []string{"../escape.key", "nested/key.bin", "nested\\key.bin", "key.bin:stream", "key\x00.bin", "NUL", "key.bin.", "."} {
				t.Run(name, func(t *testing.T) {
					if f, err := createSiteFile(root, name); err == nil {
						f.Close()
						t.Fatal("unsafe filename accepted")
					}
				})
			}
		}
		if _, err := file.WriteString("original"); err != nil {
			t.Fatal(err)
		}
		if f, err := createSiteFile(root, "key.bin"); err == nil || !os.IsExist(err) {
			if f != nil {
				f.Close()
			}
			t.Fatalf("existing file accepted: %v", err)
		}
		if data, err := os.ReadFile(filepath.Join(dir, "key.bin")); err != nil || string(data) != "original" {
			t.Fatalf("existing contents changed: %v", err)
		}
		// Windows roots hold a directory handle that prevents this rename.
		if runtime.GOOS != "windows" {
			moved := filepath.Join(fixture, "moved")
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			pinned, err := createSiteFile(root, "pinned.key")
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.Close()
			if err := checkPrivateSiteFile(pinned); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, "pinned.key")); !os.IsNotExist(err) {
				t.Fatal("creation followed a replacement directory")
			}
			if _, err := os.Stat(filepath.Join(moved, "pinned.key")); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("setup commands quote paths for the host shell", func(t *testing.T) {
		// Printed commands are for PowerShell on Windows, which also ends a
		// single-quoted string at a typographic quote, and for sh elsewhere.
		var quotes string
		for _, r := range []rune{0x2018, 0x2019, 0x201a, 0x201b} {
			quotes += string(r)
		}
		values := []string{
			filepath.Join(t.TempDir(), "site.json"),
			`C:\Site Files\it's "here" $HOME $(id) ` + "`date`;&|",
			"a" + quotes + "b",
			"x" + string(rune(0x2019)) + "; Write-Output injected; " + string(rune(0x2019)) + "y",
		}
		var script strings.Builder
		var shell *exec.Cmd
		if runtime.GOOS == "windows" {
			script.WriteString("\xef\xbb\xbf") // UTF-8 BOM for Windows PowerShell 5.1
			for _, value := range values {
				fmt.Fprintf(&script, "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(%s))\n", setupQuote(value))
			}
			path := filepath.Join(t.TempDir(), "quote.ps1")
			if err := os.WriteFile(path, []byte(script.String()), 0600); err != nil {
				t.Fatal(err)
			}
			shell = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
		} else {
			script.WriteString(`printf '%s\n'`)
			for _, value := range values {
				script.WriteString(" " + setupQuote(value))
			}
			shell = exec.Command("sh", "-c", script.String())
		}
		out, err := shell.Output()
		if err != nil {
			t.Fatalf("host shell rejected the printed quoting: %v", err)
		}
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), "\n")
		if len(lines) != len(values) {
			t.Fatalf("host shell read %d values, want %d: %q", len(lines), len(values), out)
		}
		for i, value := range values {
			got := lines[i]
			if runtime.GOOS == "windows" {
				decoded, err := base64.StdEncoding.DecodeString(got)
				if err != nil {
					t.Fatal(err)
				}
				got = string(decoded)
			}
			if got != value {
				t.Errorf("host shell read %q, want %q", got, value)
			}
		}
	})

	type received struct {
		body, encoding string
		length         int64
		target         string
	}
	requests := make(chan received, 64)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__cli_test_ready" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			requests <- received{string(body), r.Header.Get("Content-Encoding"), r.ContentLength, r.RequestURI}
		}
		if r.URL.Path == "/__cli_test_cut" { // an application that dies part way through the body it announced
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("part of a body"))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.WriteHeader(200)
	}))
	defer app.Close()
	tlsApp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests <- received{target: r.RequestURI} }))
	defer tlsApp.Close()

	// The authenticated origin uses a dedicated CA plus an exact certificate
	// identity allowlist. A different identity signed by that CA is still denied.
	type originCredential struct {
		cert            *x509.Certificate
		pair            tls.Certificate
		certPEM, keyPEM []byte
	}
	issue := func(template *x509.Certificate, issuer *originCredential) originCredential {
		_, key, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parent, signingKey := template, key
		if issuer != nil {
			parent, signingKey = issuer.cert, issuer.pair.PrivateKey.(ed25519.PrivateKey)
		}
		der, err := x509.CreateCertificate(cryptorand.Reader, template, parent, key.Public(), signingKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return originCredential{parsed, pair, certPEM, keyPEM}
	}
	now := time.Now()
	ca := issue(&x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	foreignCA := issue(&x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	serverIdentity := issue(&x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, &ca)
	t.Run("setup visitor certificate", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "visitor.crt"), filepath.Join(dir, "visitor.key")
		if err := os.WriteFile(certPath, serverIdentity.certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, serverIdentity.keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name  string
			hosts []string
			bad   bool
		}{
			{"covered DNS and IP", []string{"localhost", "127.0.0.1"}, false},
			{"one uncovered name", []string{"localhost", "other.test"}, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := checkSetupCertificate(certPath, keyPath, tc.hosts); (err != nil) != tc.bad {
					t.Fatalf("certificate validation=%v", err)
				}
			})
		}
		for _, flow := range []struct {
			name  string
			extra []string
		}{
			{"HTTPS visitor setup", []string{"https", "127.0.0.1:8443", certPath, keyPath}},
			{"TLS gateway setup", []string{"proxy", "127.0.0.1:8080", "127.0.0.1/32"}},
		} {
			t.Run(flow.name, func(t *testing.T) {
				answers := append([]string{"localhost", app.URL, "yes", "", ""}, flow.extra...)
				answers = append(answers, "detect", "no", "no", "no", "")
				var transcript bytes.Buffer
				if err := runSetup(strings.NewReader(strings.Join(answers, "\n")), &transcript, runArgs); err != nil {
					t.Fatalf("setup=%v %s", err, &transcript)
				}
			})
		}

		brokenPath := filepath.Join(dir, "broken.key")
		if err := os.WriteFile(brokenPath, []byte("not a private key"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkSetupCertificate(certPath, brokenPath, []string{"localhost"}); err == nil {
			t.Fatal("invalid visitor private key accepted")
		}
		// Setup refuses what start-up would refuse: the right key, but one everyone can read.
		openPath := filepath.Join(dir, "open.key")
		if err := os.WriteFile(openPath, serverIdentity.keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(openPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkSetupCertificate(certPath, openPath, []string{"localhost"}); runtime.GOOS != "windows" && err == nil {
			t.Fatal("a visitor key everyone can read was accepted")
		}
	})

	identities := map[string]originCredential{}
	for _, tc := range []struct {
		name          string
		serial        int64
		ca            *originCredential
		usage         x509.ExtKeyUsage
		before, after time.Time
	}{
		{"good", 4, &ca, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"wrong-site", 5, &ca, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"foreign", 4, &foreignCA, x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour)},
		{"expired", 6, &ca, x509.ExtKeyUsageClientAuth, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", 7, &ca, x509.ExtKeyUsageClientAuth, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"server-only", 8, &ca, x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(time.Hour)},
	} {
		t.Run("origin credential fixture "+tc.name, func(t *testing.T) {
			identities[tc.name] = issue(&x509.Certificate{SerialNumber: big.NewInt(tc.serial), NotBefore: tc.before, NotAfter: tc.after, ExtKeyUsage: []x509.ExtKeyUsage{tc.usage}}, tc.ca)
		})
	}

	t.Run("origin file protections", func(t *testing.T) {
		for _, tc := range []struct {
			name                               string
			mode                               os.FileMode
			symlink, directory, oversized, bad bool
		}{
			{name: "private key", mode: 0600},
			{name: "read-only service group", mode: 0640},
			{name: "world-readable key", mode: 0644, bad: true},
			{name: "group-writable key", mode: 0660, bad: true},
			{name: "symlink key", mode: 0600, symlink: true, bad: true},
			{name: "directory key", directory: true, bad: true},
			{name: "oversized key", mode: 0600, oversized: true, bad: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if runtime.GOOS == "windows" && (tc.mode == 0644 || tc.mode == 0660) {
					t.Skip("Unix permissions do not describe Windows ACLs")
				}
				dir := t.TempDir()
				path := filepath.Join(dir, "edge.key")
				data := identities["good"].keyPEM
				if tc.oversized {
					data = bytes.Repeat([]byte(" "), (64<<10)+1)
				}
				if tc.directory {
					path = dir
				} else {
					if err := os.WriteFile(path, data, tc.mode); err != nil {
						t.Fatal(err)
					}
					if runtime.GOOS != "windows" {
						if err := os.Chmod(path, tc.mode); err != nil {
							t.Fatal(err)
						}
					}
				}
				if tc.symlink {
					link := filepath.Join(dir, "link.key")
					if err := os.Symlink(path, link); err != nil {
						if runtime.GOOS == "windows" {
							t.Skip("Windows symlink creation requires host privilege")
						}
						t.Fatal(err)
					}
					path = link
				}
				got, err := readOriginFile(path, 64<<10, true)
				if (err != nil) != tc.bad {
					t.Fatalf("key acceptance: error=%v want refused=%v", err, tc.bad)
				}
				if !tc.bad && !bytes.Equal(got, data) {
					t.Fatal("key bytes changed")
				}
			})
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	originCalls := make(chan received, 64)
	authOrigin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].SerialNumber.Cmp(big.NewInt(4)) != 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/__cli_test_ready" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			originCalls <- received{string(body), r.Header.Get("Content-Encoding"), r.ContentLength, r.RequestURI}
		}
		w.WriteHeader(200)
	}))
	authOrigin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverIdentity.pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}
	authOrigin.StartTLS()
	defer authOrigin.Close()

	t.Run("listener failures close both endpoints", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			brokenTLS  bool
			lostHealth bool
		}{
			{"health listener closed before serving", false, true},
			{"visitor TLS fails before accept", true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				visitor, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer visitor.Close()
				address := visitor.Addr().String()
				healthListener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer healthListener.Close()
				healthAddress := healthListener.Addr().String()
				if tc.lostHealth {
					if err := healthListener.Close(); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				server := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
				if tc.brokenTLS {
					server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				defer server.Close()
				go func() {
					done <- serveRuntime(ctx, server, visitor, healthListener, &runtimeHealth{},
						lifecycleOptions{shutdown: time.Second}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
				}()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("lost listener was reported as a clean stop")
					}
				case <-ctx.Done():
					t.Fatal("listener failure did not stop the serving goroutines")
				}
				for _, endpoint := range []string{address, healthAddress} {
					if connection, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond); err == nil {
						connection.Close()
						t.Fatal("listener remained open after serving failed")
					}
				}
			})
		}
	})

	t.Run("origin certificate snapshot survives input mutation", func(t *testing.T) {
		identity := identities["good"].pair
		identity.Certificate = [][]byte{bytes.Clone(identity.Certificate[0])}
		// A supplied Leaf is not authority; parse the actual certificate bytes.
		identity.Leaf = identities["foreign"].cert
		target, err := url.Parse(authOrigin.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := (proxy.OriginTLS{Roots: roots, Certificate: &identity}).ClientConfig(target)
		if err != nil {
			t.Fatal(err)
		}
		clear(identity.Certificate[0])
		transport := &http.Transport{TLSClientConfig: cfg}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequest(http.MethodHead, authOrigin.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("input mutation changed the TLS identity: %v", err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("authenticated origin returned %d", response.StatusCode)
		}
		select {
		case <-originCalls:
		default:
			t.Fatal("authenticated request did not reach the origin")
		}
	})

	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	const good = `{"note":"SECRET_TOKEN_CLI_TEST","a":1}`
	var packed bytes.Buffer
	gz := gzip.NewWriter(&packed)
	if _, err := gz.Write([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compress := func(body string) string {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	// Compress below the wire limit without tripping the ratio limit, then expand above the default non-upload cap.
	random := make([]byte, 30000)
	_, _ = rand.New(rand.NewSource(1)).Read(random)
	largeJSON := `{"data":"` + strings.Repeat(base64.StdEncoding.EncodeToString(random), 4) + `"}`
	upload := func(name, content string) string {
		return "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name + "\"\r\nContent-Type: text/plain\r\n\r\n" + content + "\r\n--B--\r\n"
	}
	unix := runtime.GOOS != "windows" // file modes mean nothing on Windows, so a check of them passes there
	onUnix := func(s string) string {
		if unix {
			return s
		}
		return ""
	}
	tests := []struct {
		site                                                                        string
		health                                                                      bool
		healthAlias                                                                 string
		preflight                                                                   bool
		trustOrigin                                                                 bool
		originAuth                                                                  string
		probeHTTP                                                                   bool
		apiSpec                                                                     string
		headers                                                                     map[string]string
		alsoRules                                                                   []int
		statsRule                                                                   int
		statsBlocked, statsMonitored                                                uint64
		repeat                                                                      int
		apiRate                                                                     int
		apiPaths                                                                    string
		statuses                                                                    []int
		targets, forwarding, extraArgs                                              []string
		name, mode, policy, method, target, ct, body, encoding, logRule, originBody string
		says                                                                        string // what the log of a failure or a preflight must say
		allowEncoding, fails, policyDir                                             bool
		status                                                                      int
	}{
		{name: "expanded IPv6 health address works", health: true, healthAlias: "ipv6-expanded", method: "GET", target: "/page", status: 200},
		{name: "mapped IPv4 health address works", health: true, healthAlias: "ipv4-mapped", method: "GET", target: "/page", status: 200},
		{name: "version cannot bypass health action", extraArgs: []string{"-probe", "ready", "-version"}, fails: true},
		{name: "private health probes preserve forwarding", health: true, method: "GET", target: "/page", status: 200},
		{name: "visitor readiness path still inspected", health: true, mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/readyz?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403},
		{name: "public health binding refused", extraArgs: []string{"-health-listen", "0.0.0.0:8082"}, fails: true},
		{name: "wildcard health binding refused", extraArgs: []string{"-health-listen", ":8082"}, fails: true},
		{name: "health hostname refused", extraArgs: []string{"-health-listen", "localhost:8082"}, fails: true},
		{name: "health ephemeral port refused", extraArgs: []string{"-health-listen", "127.0.0.1:0"}, fails: true},
		{name: "negative drain delay refused", extraArgs: []string{"-drain-delay", "-1s"}, fails: true},
		{name: "drain must fit shutdown budget", extraArgs: []string{"-drain-delay", "1s", "-shutdown-timeout", "1s"}, fails: true},
		{name: "unbounded shutdown refused", extraArgs: []string{"-shutdown-timeout", "0"}, fails: true},
		{name: "excess shutdown refused", extraArgs: []string{"-shutdown-timeout", "11m"}, fails: true},
		{name: "probe kind refused", extraArgs: []string{"-probe", "drain", "-health-listen", "127.0.0.1:8082"}, fails: true},
		{name: "probe needs private listener", extraArgs: []string{"-probe", "live"}, fails: true},
		{name: "probe cannot run deployment check", extraArgs: []string{"-probe", "live", "-health-listen", "127.0.0.1:8082", "-check"}, fails: true},
		{name: "origin authentication forwards good traffic", originAuth: "good", method: "GET", target: "/page", status: 200, repeat: 4},
		{name: "origin identity does not skip inspection", originAuth: "good", method: "GET", target: "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", extraArgs: []string{"-mode", "block"}, mode: "block", status: 403},
		{name: "origin certificate preflight confirms HTTP acceptance", originAuth: "good", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, preflight: true, probeHTTP: true},
		{name: "origin refuses missing certificate", originAuth: "none", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin refuses foreign CA certificate", originAuth: "foreign", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin refuses different identity from its CA", originAuth: "wrong-site", extraArgs: []string{"-check", "-check-origin", "-check-origin-http"}, fails: true},
		{name: "origin expired certificate refuses startup", originAuth: "expired", extraArgs: []string{"-check"}, fails: true},
		{name: "origin future certificate refuses startup", originAuth: "future", extraArgs: []string{"-check"}, fails: true},
		{name: "origin server certificate cannot serve as client identity", originAuth: "server-only", extraArgs: []string{"-check"}, fails: true},
		{name: "origin key mismatch refuses startup", originAuth: "mismatch", extraArgs: []string{"-check"}, fails: true},
		{name: "origin certificate needs paired key", extraArgs: []string{"-origin-client-cert", "missing.pem", "-check"}, fails: true},
		{name: "origin TLS settings refuse plaintext upstream", extraArgs: []string{"-origin-ca-file", "missing.pem", "-check"}, fails: true},
		{name: "HTTP preflight requires explicit actions", extraArgs: []string{"-check-origin-http"}, fails: true},
		{name: "site check accepts trusted origin certificate", site: `{"version":1,"flags":{"upstream":"$TLSORIGIN","origin-allow":"127.0.0.1/32"}}`, extraArgs: []string{"-check", "-check-origin"}, preflight: true, trustOrigin: true},
		{name: "site check rejects untrusted origin certificate", site: `{"version":1,"flags":{"upstream":"$TLSORIGIN","origin-allow":"127.0.0.1/32"}}`, extraArgs: []string{"-check", "-check-origin"}, fails: true},
		{name: "site check rejects private DNS without allowance", site: `{"version":1,"flags":{"upstream":"$DNSORIGIN"}}`, extraArgs: []string{"-check", "-check-origin"}, fails: true},
		{name: "site shipped local example", site: "local-example", method: "GET", target: "/page", status: 200},
		{name: "site config serves good request", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\",\"local-rules\":true,\"max-body\":1048576,\"ddos-rate\":50.5,\"eval-budget\":\"2s\"}}", method: "GET", target: "/page", status: 200},
		{name: "site config blocks injection", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", method: "GET", target: "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403},
		{name: "site config format enforcement", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"block\",\"formats-mode\":\"block\"}}", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "explicit false overrides file true", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"allow-request-encoding\":true}}", mode: "off", extraArgs: []string{"-allow-request-encoding=false"}, status: 200},
		{name: "explicit enforcement overrides file monitor", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"mode\":\"off\",\"formats-mode\":\"monitor\"}}", mode: "block", ct: "application/json", body: "{\"a\":1,\"a\":2}", status: 400},
		{name: "site config private origin needs allowance", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\"}}", fails: true},
		{name: "site check does not listen or require inherited socket", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"systemd-socket\":true}}", preflight: true, extraArgs: []string{"-check"}},
		{name: "site check verifies origin connectivity without HTTP", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\"}}", preflight: true, extraArgs: []string{"-check", "-check-origin"}},
		{name: "site check validates confine port list", site: "{\"version\":1,\"flags\":{\"upstream\":\"$ORIGIN\",\"origin-allow\":\"127.0.0.1/32\",\"confine\":true,\"confine-connect\":\"invalid\"}}", fails: true, extraArgs: []string{"-check"}, says: "-confine-connect:"},
		// A confined proxy can connect only to the listed ports: without the origin's it would pass the check and then refuse
		// every request, and without its own upload directory it would refuse every upload.
		{name: "confine refuses an origin port it may not connect to", extraArgs: []string{"-check", "-confine", "-upload-dir", "$UPLOADS"}, fails: true, says: "must be listed in -confine-connect"},
		{name: "confine without an upload directory warns that uploads will be refused", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53"}, preflight: true, says: "uploads with file parts will be refused"},
		{name: "confine refuses an upload directory its group may write", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53", "-upload-dir", "$SHAREDUPLOADS"}, fails: unix, preflight: !unix, says: onUnix("-upload-dir: mode 0770")},
		{name: "confine check passes with the origin port and an upload directory", extraArgs: []string{"-check", "-confine", "-confine-connect", "$ORIGINPORT,53", "-upload-dir", "$UPLOADS"}, preflight: true},
		// The reverse proxy's own line about a body the application cut short is JSON, named, without the addresses.
		{name: "an application that cuts its body short is logged as the origin's error", mode: "block", method: "GET", target: "/__cli_test_cut", status: 0, says: `"server":"origin"`},
		{name: "site check permits named listening port", extraArgs: []string{"-check", "-listen", "127.0.0.1:http"}, preflight: true},
		{name: "check validates listen syntax", extraArgs: []string{"-check", "-listen", "invalid"}, fails: true},
		{name: "check validates upstream port", extraArgs: []string{"-check", "-upstream", "http://127.0.0.1:0"}, fails: true},
		{name: "check origin requires check", extraArgs: []string{"-check-origin"}, fails: true},
		{name: "contract correct URL query", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fassets.example.test%2Fpublic%2Fphoto.png", status: 200},
		{name: "contract correct JSON URL", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png"}`, status: 200},
		{name: "contract attacker host", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fevil.example%2Fpublic%2Fphoto.png", status: 400, logRule: `"rule":5003103`},
		{name: "contract private IP", mode: "block", apiSpec: "example", method: "GET", target: "/api/import?src=http%3A%2F%2F127.0.0.1%2F", status: 400, logRule: `"rule":5003103`},
		{name: "contract userinfo bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test@evil.example/public/photo.png"}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract escaped JSON host bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://\u0065vil.example/public/photo.png"}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract missing URL", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{}`, status: 400, logRule: `"rule":5003108`},
		{name: "contract independently detects duplicate JSON", mode: "block", apiSpec: "example", policy: `{"rules":{"json-duplicate-key":"off"}}`, target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png","src":"https://evil.example/x"}`, status: 400, logRule: `"rule":5003006`},
		{name: "contract refuses JSON relabeled text", mode: "block", apiSpec: "example", target: "/api/import", ct: "text/plain", body: `{"src":"https://evil.example/x"}`, status: 415, logRule: `"rule":5002040`},
		{name: "contract unknown privileged JSON field", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `{"src":"https://assets.example.test/public/photo.png","role":"admin"}`, status: 400, logRule: `"rule":5003109`},
		{name: "contract JSON array shape bypass", mode: "block", apiSpec: "example", target: "/api/import", ct: "application/json", body: `[{"src":"https://assets.example.test/public/photo.png"}]`, status: 400, logRule: `"rule":5003108`},
		{name: "contract duplicate scalar", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&user_id=2", status: 400, logRule: `"rule":5003103`},
		{name: "contract scalar bracket alias", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&user_id_extra[]=2", status: 400, logRule: `"rule":5003113`},
		{name: "contract optional array bracket alias", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&tags[]=red", status: 400, logRule: `"rule":5003113`},
		{name: "contract declared repeated array", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=1&tags=red&tags=blue", status: 200},
		{name: "contract typed XPath protection", mode: "block", apiSpec: "example", method: "GET", target: "/api/search?user_id=0%20or%20true%28%29", status: 400, logRule: `"rule":5003103`},
		{name: "contract monitor URL", mode: "monitor", apiSpec: "example", method: "GET", target: "/api/import?src=https%3A%2F%2Fevil.example%2Fx", extraArgs: []string{"-api-spec-mode", "monitor"}, status: 200, logRule: `"rule":5003103`},
		{name: "contract block needs strict formats", mode: "monitor", apiSpec: "example", fails: true},
		{name: "contract invalid mode", mode: "block", extraArgs: []string{"-api-spec-mode", "ignored"}, fails: true},
		{name: "contract malformed specification", mode: "block", apiSpec: `{`, fails: true},
		{name: "contract empty specification", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{}}`, fails: true},
		{name: "contract empty required body media", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"post":{"requestBody":{"required":true,"content":{}}}}}}`, fails: true},
		{name: "contract unsupported constraints", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"get":{"parameters":[{"name":"x","in":"query","schema":{"type":"string","pattern":"(?=a)"}}]}}}}`, fails: true},
		{name: "contract object parameter", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"get":{"parameters":[{"name":"x","in":"query","style":"deepObject","schema":{"type":"object"}}]}}}}`, fails: true},
		{name: "contract non JSON body", mode: "block", apiSpec: `{"openapi":"3.0.3","paths":{"/api/x":{"post":{"requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"x":{"type":"string"}}}}}}}}}}`, fails: true},
		{name: "live supplemental XPath", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%27%20or%20true%28%29%20or%20%27a%27%3D%27b", status: 403, logRule: `"rule":5006001`},
		{name: "live heldout XPath comments", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%27%20or%20%28%3Acomment%3A%29%20true%28%29", status: 403, logRule: `"rule":5006009`},
		{name: "live heldout deep traversal", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%2525252e%2525252e%2525252fetc%2525252fpasswd", status: 403, logRule: `"rule":5006006`},
		{name: "live local rules detect mode", mode: "block", extraArgs: []string{"-mode", "detect"}, method: "GET", target: "/api?q=%27%20or%20true%28%29", status: 200, logRule: `"rule":5006001`},
		{name: "live local rules opt out", mode: "block", extraArgs: []string{"-mode", "block", "-local-rules=false"}, method: "GET", target: "/api?q=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH", status: 200},
		{name: "live supplemental quoted shell", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/api?q=%3Bi%27%27d", status: 403, logRule: `"rule":5006003`},
		{name: "live exploit path", mode: "block", extraArgs: []string{"-mode", "block"}, method: "GET", target: "/wp-content/uploads/2024/x.php.jpg", status: 403, logRule: `"rule":5006011,"severity":"critical","rule_msg":"Exploit or web shell path"`},
		{name: "live parameter collision", mode: "block", ct: "application/x-www-form-urlencoded", body: "user.name=a&user_name=b", status: 400, logRule: `"rule":5002608`},
		{name: "live XML attribute bypass", mode: "block", extraArgs: []string{"-mode", "block"}, ct: "application/xml", body: `<input value="' or true() or 'a'='b"/>`, status: 403, logRule: `"rule":5006001`},
		{name: "default monitor logs a GET mutation", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: `"rule":5002310`},
		{name: "block GET mutation with CRS off", mode: "block", method: "GET", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: `"rule":5002310`},
		{name: "block HEAD mutation with CRS off", mode: "block", method: "HEAD", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD protocol name case alias", mode: "block", method: "HEAD", target: "/graphql?%51uery=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD protocol alias independent transport guard", mode: "block", policy: "{\"rules\":{\"graphql-safe-method-mutation\":\"off\"}}", method: "HEAD", target: "/api/gql?QUERY=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "POST JSON protocol name case alias", mode: "block", target: "/graphql", ct: "application/json", body: "{\"Query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002308"},
		{name: "independent transport guard with mutation rule off", mode: "block", policy: "{\"rules\":{\"graphql-safe-method-mutation\":\"off\"}}", method: "HEAD", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315", repeat: 3,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002315, statsBlocked: 3},
		{name: "protocol alias method override multiple detection totals", mode: "monitor", method: "HEAD", target: "/api/gql?%51uery=mutation%7BSECRET_TOKEN_CLI_TEST%7D&_method=POST", status: 200,
			logRule: "\"rule\":5002314", alsoRules: []int{5002315, 5002308, 5002317}, repeat: 2,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002315, statsMonitored: 2},
		{name: "discovered GraphQL through PUT form", mode: "block", method: "PUT", target: "/api/gql", ct: "application/x-www-form-urlencoded", body: "query=mutation%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "discovered GraphQL after an empty batch prefix", mode: "block", method: "PUT", target: "/api/gql", ct: "application/json", body: "[{}, {\"query\":\"mutation{deleteUser}\"}]", status: 403, logRule: "\"rule\":5002315"},
		{name: "GraphQL discovery beyond retained batch elements", mode: "block", target: "/api/gql", ct: "application/json", body: "[" + strings.Repeat("{},", 12) + "{\"query\":\"mutation{deleteUser}\"}]", status: 400, logRule: "\"rule\":5002305"},
		{name: "conflicting URL and body selection", mode: "block", method: "POST", target: "/graphql?operationName=Read", ct: "application/json", body: "{\"query\":\"query Read{a} mutation Write{b}\",\"operationName\":\"Write\"}", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only selection", mode: "block", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", ct: "application/json", body: "{\"operationName\":\"Write\"}", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only form selection", mode: "block", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", ct: "application/x-www-form-urlencoded", body: "operationName=Write", status: 400, logRule: "\"rule\":5002316"},
		{name: "discovered URL operation with body-only variables", mode: "block", target: "/api/gql?query=%7Ba%7D", ct: "application/json", body: "{\"variables\":{\"admin\":true}}", status: 400, logRule: "\"rule\":5002316"},
		{name: "noncanonical HEAD token", mode: "off", method: "head", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5000043"},
		{name: "GraphQL method override URL metadata", mode: "block", target: "/graphql?%5Fmethod=HEAD", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL method override form metadata", mode: "block", target: "/api/gql", ct: "application/x-www-form-urlencoded", body: "_method=GET&query=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL method override JSON metadata", mode: "block", target: "/graphql", ct: "application/json", body: "{\"_method\":\"HEAD\",\"query\":\"mutation{deleteUser}\"}", status: 400, logRule: "\"rule\":5002317"},
		{name: "GraphQL variables method field remains valid", mode: "block", target: "/graphql", ct: "application/json", body: "{\"query\":\"mutation($x:Input){update(x:$x)}\",\"variables\":{\"x\":{\"_method\":\"GET\"}}}", status: 200},
		{name: "method override metadata monitoring totals", mode: "monitor", target: "/graphql?%5Fmethod=GET", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 200, logRule: "\"rule\":5002317", repeat: 2,
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002317, statsMonitored: 2},
		{name: "method override header hard refusal", mode: "off", method: "POST", ct: "application/json", body: good, headers: map[string]string{"X-HTTP-Method-Override": "GET"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "underscore method override hard refusal", mode: "off", headers: map[string]string{"X_HTTP_METHOD_OVERRIDE": "GET"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "method override connection token hard refusal", mode: "off", headers: map[string]string{"X-Method-Override": "GET", "Connection": "close, X-Method-Override"}, status: 400, logRule: "\"rule\":5000044"},
		{name: "mixed variables and form transport", mode: "block", target: "/graphql?variables=%7B%7D", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BdeleteUser%7D", status: 400, logRule: "\"rule\":5002316"},
		{name: "mixed raw GraphQL and URL transport", mode: "block", target: "/api/gql?%65xtensions=%7B%7D", ct: "application/graphql", body: "mutation{deleteUser}", status: 400, logRule: "\"rule\":5002316"},
		{name: "mixed transport monitor logs both layers", mode: "monitor", method: "HEAD", target: "/graphql?operationName=Write", ct: "application/json", body: "{\"query\":\"mutation Write{deleteUser}\"}", status: 200,
			logRule: "\"rule\":5002316", alsoRules: []int{5002009, 5002314, 5002315},
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002316, statsMonitored: 1},
		{name: "ordinary metadata with POST mutation", mode: "block", target: "/graphql?locale=en", ct: "application/json", body: "{\"query\":\"mutation{deleteUser}\"}", status: 200},
		{name: "HEAD extension-only request transport refused", mode: "block", method: "HEAD", target: "/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22sha256Hash%22%3A%22abc%22%7D%7D", status: 403, logRule: "\"rule\":5002315"},
		{name: "blocked bypass totals", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BSECRET_TOKEN_CLI_TEST%7D", repeat: 3, status: 403, logRule: "\"rule\":5002314",
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsBlocked: 3},
		{name: "multiple independent bypass detections", mode: "monitor", method: "HEAD", target: "/graphql", ct: "application/json",
			body: "{\"query\":\"{a}\",\"query\":\"mutation{SECRET_TOKEN_CLI_TEST}\"}", status: 200, logRule: "\"rule\":5002314", alsoRules: []int{5002009, 5002103, 5002315},
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsMonitored: 1},
		{name: "monitored related bypass totals", mode: "monitor", method: "OPTIONS", target: "/graphql", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BSECRET_TOKEN_CLI_TEST%7D", repeat: 2, status: 200, logRule: "\"rule\":5002314",
			extraArgs: []string{"-formats-stats-interval", "100ms"}, statsRule: 5002314, statsMonitored: 2},
		{name: "invalid negative stats interval", extraArgs: []string{"-formats-stats-interval", "-1s"}, fails: true},
		{name: "invalid excessive stats frequency", extraArgs: []string{"-formats-stats-interval", "50ms"}, fails: true},
		{name: "invalid long stats interval", extraArgs: []string{"-formats-stats-interval", "25h"}, fails: true},
		{name: "block discovered HEAD mutation", mode: "block", method: "HEAD", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "block OPTIONS mutation with CRS off", mode: "block", method: "OPTIONS", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "block TRACE mutation with CRS off", mode: "block", method: "TRACE", target: "/api/gql?query=mutation%7BdeleteUser%7D", status: 403},
		{name: "monitor HEAD mutation", mode: "monitor", method: "HEAD", target: "/graphql?query=mutation%7BdeleteUser%7D", status: 200, logRule: "\"rule\":5002314"},
		{name: "ordinary OPTIONS preflight", mode: "block", method: "OPTIONS", target: "/graphql?version=1", status: 200},
		{name: "selected HEAD query transport refused", mode: "block", method: "HEAD", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 403, logRule: "\"rule\":5002315"},
		{name: "HEAD escaped protocol name and operation", mode: "block", method: "HEAD", target: "/api/gql?%71uery=%6d%75%74%61%74%69%6f%6e%7BdeleteUser%7D", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD selected mutation via fragment", mode: "block", method: "HEAD", target: "/api/gql?query=fragment+F+on+User%7Bid%7D+mutation+Write%7BdeleteUser%7B...F%7D%7D&operationName=Write", status: 403, logRule: "\"rule\":5002314"},
		{name: "HEAD batch mutation in permitted body", mode: "block", policy: "{\"rules\":{\"body-on-get\":\"off\",\"graphql-http-method\":\"off\"}}", method: "HEAD", target: "/graphql", ct: "application/json", body: "[{\"query\":\"{a}\"},{\"query\":\"mutation{deleteUser}\"}]", status: 403, logRule: "\"rule\":5002314"},
		{name: "monitor related OPTIONS form mutation", mode: "monitor", method: "OPTIONS", target: "/graphql", ct: "application/x-www-form-urlencoded", body: "%71uery=mutation%7BdeleteUser%7D", status: 200, logRule: "\"rule\":5002314"},
		{name: "HEAD duplicate operationName", mode: "block", method: "HEAD", target: "/api/gql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read&%6fperationName=Write", status: 400, logRule: "\"rule\":5002308"},
		{name: "selected GET query beside mutation", mode: "block", method: "GET", target: "/graphql?query=query+Read%7Ba%7D+mutation+Write%7Bb%7D&operationName=Read", status: 200},
		{name: "valid JSON", mode: "block", ct: "application/json", body: good, status: 200},
		{name: "query malformed escape", mode: "block", method: "GET", target: "/api?x=%zz", status: 400},
		{name: "query raw semicolon", mode: "block", method: "GET", target: "/api?x=1;y=2", status: 400},
		{name: "query escaped NUL", mode: "block", ct: "application/json", body: good, target: "/api?x=%00", status: 400},
		{name: "query invalid UTF-8", mode: "block", method: "GET", target: "/api?x=%ff", status: 400},
		{name: "query prototype key", mode: "block", method: "GET", target: "/api?user%5B__proto__%5D%5Badmin%5D=1", status: 400},
		{name: "valid query preserves target", mode: "block", method: "GET", target: "/api?q=a%3Bb%26c&tag%5B%5D=red&tag%5B%5D=blue", status: 200},
		{name: "query duplicate monitor", mode: "block", method: "GET", target: "/api?id=1&%69D=2", status: 200, logRule: `"rule":5002802`},
		{name: "query duplicate opt-in block", mode: "block", policy: `{"rules":{"query-duplicate-param":"block"}}`, method: "GET", target: "/api?id=1&id=2", status: 400},
		{name: "query semicolon monitor forwards unchanged", mode: "monitor", method: "GET", target: "/api?x=1;y=2", status: 200, logRule: `"rule":5002805`},
		{name: "query byte cap", mode: "block", policy: `{"max_query_bytes":4}`, method: "GET", target: "/api?a=123", status: 414},
		{name: "query count policy", mode: "block", policy: `{"query":{"max_params":1}}`, method: "GET", target: "/api?a=1&b=2", status: 400},
		{name: "query monitor cap still checks body", mode: "block", policy: `{"max_query_bytes":4,"rules":{"query-too-large":"monitor"}}`, target: "/api?a=123", ct: "application/json", body: `{"a":1,"a":2}`, status: 400, logRule: `"rule":5002103`},
		{name: "duplicate JSON key", mode: "block", ct: "application/json", body: `{"a":1,"a":2}`, status: 400, logRule: `"rule":5002103`},
		{name: "XML external entity", mode: "block", ct: "text/xml", body: `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`, status: 400},
		{name: "custom GraphQL depth", mode: "block", policy: `{"graphql":{"max_depth":2}}`, target: "/graphql", ct: "application/json", body: `{"query":"{a{b{c}}}"}`, status: 400},
		{name: "aggregate GraphQL budget blocks a batch", mode: "block", policy: `{"graphql":{"max_request_fields":3}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 400, logRule: `"rule":5002311`},
		{name: "aggregate budget is local to each request", mode: "block", policy: `{"graphql":{"max_request_fields":4}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 200, repeat: 3},
		{name: "aggregate budget monitoring", mode: "monitor", policy: `{"graphql":{"max_request_fields":3}}`, target: "/graphql", ct: "application/json", body: `[{"query":"{a b}"},{"query":"{c d}"}]`, status: 200, logRule: `"rule":5002311`},
		{name: "explicit monitor overrides policy", mode: "monitor", policy: `{"monitor":false}`, ct: "application/json", body: `{"a":1,"a":2}`, status: 200, logRule: `"rule":5002103`},
		{name: "explicit block overrides policy monitor", mode: "block", policy: `{"monitor":true}`, ct: "application/json", body: `{"a":1,"a":2}`, status: 400},
		{name: "off forwards uninspected JSON", mode: "off", ct: "application/json", body: `{"a":1,"a":2}`, status: 200},
		{name: "bounded gzip decompressed", mode: "block", ct: "application/json", body: packed.String(), originBody: good, encoding: "gzip", allowEncoding: true, status: 200},
		{name: "decompressed body respects proxy limit", mode: "block", ct: "application/json", body: compress(largeJSON), encoding: "gzip", allowEncoding: true, status: 413},
		{name: "decompressed body limit survives monitor mode", mode: "monitor", ct: "application/json", body: compress(largeJSON), encoding: "gzip", allowEncoding: true, status: 413},
		{name: "compressed executable upload refused", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("shell.php", "ordinary text")), encoding: "gzip", allowEncoding: true, status: 403},
		{name: "compressed script content refused", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("photo.txt", "<?php echo 1; ?>")), encoding: "gzip", allowEncoding: true, status: 403},
		{name: "compressed ordinary upload", mode: "block", ct: "multipart/form-data; boundary=B", body: compress(upload("photo.txt", "ordinary text")), originBody: upload("photo.txt", "ordinary text"), encoding: "gzip", allowEncoding: true, status: 200},
		{name: "gzip opt-in required", mode: "block", ct: "application/json", body: packed.String(), encoding: "gzip", status: 415},
		{name: "corrupt gzip refused", mode: "block", ct: "application/json", body: "bad-gzip", encoding: "gzip", allowEncoding: true, status: 400},
		{name: "API quota holds with CRS and formats off", mode: "off", apiRate: 2, target: "/api/orders", statuses: []int{200, 200, 429}, logRule: `"rule":5000042`},
		{name: "API prefixes share a budget", mode: "off", apiRate: 2, targets: []string{"/api/orders", "/graphql", "/api/users"}, statuses: []int{200, 200, 429}},
		{name: "API forwarding spoof cannot rotate identity", mode: "off", apiRate: 1, target: "/api", forwarding: []string{"198.51.100.1", "198.51.100.2"}, statuses: []int{200, 429}},
		{name: "trusted clients have separate quotas", mode: "off", apiRate: 1, target: "/api", extraArgs: []string{"-trusted-proxies", "127.0.0.0/8"}, forwarding: []string{"198.51.100.1", "198.51.100.1", "198.51.100.2"}, statuses: []int{200, 429, 200}},
		{name: "custom API prefix", mode: "off", apiRate: 1, apiPaths: "/internal", target: "/internal/orders", statuses: []int{200, 429}},
		{name: "API prefix requires a segment boundary", mode: "off", apiRate: 1, target: "/apiary", statuses: []int{200, 200}},
		{name: "API and login budgets are separate", mode: "off", apiRate: 1, extraArgs: []string{"-wordpress", "-login-per-minute", "1"}, targets: []string{"/wp-login.php", "/api", "/wp-login.php", "/api"}, statuses: []int{200, 200, 429, 429}},
		{name: "negative API limit refuses startup", mode: "off", apiRate: -1, fails: true},
		{name: "excess API limit refuses startup", mode: "off", apiRate: 100001, fails: true},
		{name: "invalid API prefix refuses startup", mode: "off", apiRate: 1, apiPaths: "/api?x=1", fails: true},
		{name: "unknown mode refuses startup", mode: "enforce", fails: true},
		{name: "off with encoding refuses startup", mode: "off", allowEncoding: true, fails: true},
		{name: "off with policy refuses startup", mode: "off", policy: `{}`, fails: true},
		{name: "malformed policy refuses startup", mode: "block", policy: `{`, fails: true},
		{name: "unknown policy field refuses startup", mode: "block", policy: `{"graphql":{"max_dept":2}}`, fails: true},
		{name: "invalid policy limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":-1}}`, fails: true},
		{name: "null policy refuses startup", mode: "block", policy: `null`, fails: true},
		{name: "null limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":null}}`, fails: true},
		{name: "duplicate limit refuses startup", mode: "block", policy: `{"graphql":{"max_depth":2,"max_depth":12}}`, fails: true},
		{name: "duplicate rule refuses startup", mode: "block", policy: `{"rules":{"json-duplicate-key":"block","json-duplicate-key":"off"}}`, fails: true},
		{name: "case alias refuses startup", mode: "block", policy: `{"graphql":{"MAX_DEPTH":2}}`, fails: true},
		{name: "policy directory refuses startup", mode: "block", policyDir: true, fails: true},
		{name: "policy over file cap refuses startup", mode: "block", policy: `{}` + strings.Repeat(" ", maxFormatsPolicyBytes), fails: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.trustOrigin && runtime.GOOS != "linux" {
				t.Skip("Linux SSL_CERT_FILE tests system-root overrides; Windows uses the native certificate store")
			}
			for len(originCalls) > 0 {
				<-originCalls
			}
			for len(requests) > 0 {
				<-requests // a failing previous subtest must not contaminate this one's origin evidence
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
			args := []string{"-listen", addr, "-upstream", app.URL, "-origin-allow", "127.0.0.0/8", "-mode", "off"}
			if tc.site == "local-example" {
				data, err := os.ReadFile("../../docs/examples/site-local.json")
				if err != nil {
					t.Fatal(err)
				}
				tc.site = strings.ReplaceAll(string(data), "http://127.0.0.1:8081", app.URL)
			}
			if tc.site != "" {
				path := filepath.Join(t.TempDir(), "site.json")
				if err := os.WriteFile(path, []byte(strings.NewReplacer("$ORIGIN", app.URL, "$TLSORIGIN", tlsApp.URL, "$DNSORIGIN", strings.ReplaceAll(app.URL, "127.0.0.1", "localhost")).Replace(tc.site)), 0600); err != nil {
					t.Fatal(err)
				}
				args = []string{"-listen", addr, "-config", path}
			}
			args = append(args, tc.extraArgs...)
			if strings.Contains(strings.Join(tc.extraArgs, " "), "$") {
				_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(app.URL, "http://"))
				uploads, err := os.MkdirTemp("", "carnical-uploads") // plain characters, which the upload directory must have
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(uploads) })
				// A Windows temp directory can be named by its 8.3 short name (C:\Users\RUNNER~1\...), whose ~ the setting
				// refuses; the long name is the same directory in plain characters.
				long, err := filepath.EvalSymlinks(uploads)
				if err != nil {
					t.Fatal(err)
				}
				uploads = long
				shared := filepath.Join(uploads, "shared")
				if err := os.Mkdir(shared, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(shared, 0o770); err != nil {
					t.Fatal(err)
				}
				for i := range args {
					args[i] = strings.NewReplacer("$ORIGINPORT", originPort, "$SHAREDUPLOADS", shared, "$UPLOADS", uploads).Replace(args[i])
				}
			}

			if tc.originAuth != "" {
				dir := t.TempDir()
				caPath := filepath.Join(dir, "origin-ca.pem")
				if err := os.WriteFile(caPath, ca.certPEM, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-upstream", authOrigin.URL, "-origin-ca-file", caPath)
				if tc.originAuth != "none" {
					name := tc.originAuth
					if name == "mismatch" {
						name = "good"
					}
					identity := identities[name]
					certPath, keyPath := filepath.Join(dir, "edge.pem"), filepath.Join(dir, "edge.key")
					key := identity.keyPEM
					if tc.originAuth == "mismatch" {
						key = identities["wrong-site"].keyPEM
					}
					if err := os.WriteFile(certPath, identity.certPEM, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(keyPath, key, 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "-origin-client-cert", certPath, "-origin-client-key", keyPath)
				}
			}

			if tc.apiSpec != "" {
				data := []byte(tc.apiSpec)
				if tc.apiSpec == "example" {
					data, err = os.ReadFile("../../docs/examples/api-contract.json")
					if err != nil {
						t.Fatal(err)
					}
				}
				path := filepath.Join(t.TempDir(), "api.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-api-spec", path)
			}
			if tc.apiRate != 0 {
				args = append(args, "-api-per-minute", fmt.Sprint(tc.apiRate))
			}
			if tc.apiPaths != "" {
				args = append(args, "-api-rate-paths", tc.apiPaths)
			}
			if tc.mode != "" {
				args = append(args, "-formats-mode", tc.mode)
			}
			if tc.allowEncoding {
				args = append(args, "-allow-request-encoding")
			}
			if tc.policy != "" || tc.policyDir {
				path := t.TempDir()
				if !tc.policyDir {
					path = filepath.Join(path, "formats.json")
					if err := os.WriteFile(path, []byte(tc.policy), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args = append(args, "-formats-policy", path)
			}
			healthAddress := ""
			if tc.health {
				network, binding := "tcp", "127.0.0.1:0"
				if tc.healthAlias == "ipv6-expanded" {
					network, binding = "tcp6", "[::1]:0"
				}
				ln, err := net.Listen(network, binding)
				if err != nil {
					t.Fatal(err)
				}
				healthAddress = ln.Addr().String()
				_, port, err := net.SplitHostPort(healthAddress)
				if err != nil {
					t.Fatal(err)
				}
				switch tc.healthAlias {
				case "ipv6-expanded":
					healthAddress = "[0:0:0:0:0:0:0:1]:" + port
				case "ipv4-mapped":
					healthAddress = "[::ffff:127.0.0.1]:" + port
				}
				if err := ln.Close(); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-health-listen", healthAddress)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, args...)
			if tc.trustOrigin {
				path := filepath.Join(t.TempDir(), "ca.pem")
				data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsApp.Certificate().Raw})
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+path)
			}
			logPath := filepath.Join(t.TempDir(), "proxy.log")
			logs, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			cmd.Stdout, cmd.Stderr = logs, logs
			if tc.preflight {
				if err := cmd.Run(); err != nil {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("preflight failed: %v\n%s", err, data)
				}
				data, _ := os.ReadFile(logPath)
				if !bytes.Contains(data, []byte(`"msg":"configuration checked"`)) {
					t.Fatal("missing preflight result")
				}
				if !bytes.Contains(data, []byte(tc.says)) {
					t.Fatalf("the preflight did not say %q:\n%s", tc.says, data)
				}
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Fatal("preflight opened a listener")
				}
				if tc.probeHTTP {
					select {
					case got := <-originCalls:
						if got.target != "/" || got.body != "" {
							t.Fatal("HTTP probe changed target or sent a body")
						}
					default:
						t.Fatal("HTTP probe did not reach authenticated origin")
					}
				} else if len(originCalls) != 0 {
					t.Fatal("local preflight sent HTTP")
				}
				if len(requests) != 0 {
					t.Fatal("preflight sent an HTTP request")
				}
				return
			}
			if tc.fails {
				if err := cmd.Run(); err == nil || ctx.Err() != nil {
					t.Fatalf("invalid configuration did not fail promptly: %v", err)
				}
				if data, _ := os.ReadFile(logPath); !bytes.Contains(data, []byte(tc.says)) {
					t.Fatalf("failed, but not saying %q:\n%s", tc.says, data)
				}
				if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					conn.Close()
					t.Fatal("invalid configuration opened a listener")
				}
				if len(originCalls) != 0 {
					t.Fatal("refused origin identity reached the application")
				}
				return
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				cancel()
				if !waited {
					_ = cmd.Wait()
				}
			}()
			url := "http://" + addr
			for {
				resp, err := client.Get(url + "/__cli_test_ready")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						break
					}
				}
				if ctx.Err() != nil {
					t.Fatal("firewall did not become ready")
				}
				time.Sleep(25 * time.Millisecond)
			}
			if tc.health {
				for _, kind := range []string{"live", "ready"} {
					probe := exec.CommandContext(ctx, bin, "-health-listen", healthAddress, "-probe", kind)
					probe.Env = append(os.Environ(), "HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=")
					if out, err := probe.CombinedOutput(); err != nil {
						t.Fatalf("private %s probe: %v %s", kind, err, out)
					}
				}
			}
			method, target := tc.method, tc.target
			if method == "" {
				method = "POST"
			}
			if target == "" {
				target = "/api/save"
			}
			for i := range max(tc.repeat, len(tc.statuses), 1) {
				want, requestTarget := tc.status, target
				if len(tc.statuses) > 0 {
					want = tc.statuses[i]
				}
				if len(tc.targets) > 0 {
					requestTarget = tc.targets[i]
				}
				req, err := http.NewRequest(method, url+requestTarget, strings.NewReader(tc.body))
				if err != nil {
					t.Fatal(err)
				}
				if tc.ct != "" {
					req.Header.Set("Content-Type", tc.ct)
				}
				for name, value := range tc.headers {
					req.Header.Set(name, value)
				}
				if len(tc.forwarding) > 0 {
					req.Header.Set("X-Forwarded-For", tc.forwarding[i])
				}
				if tc.encoding != "" {
					req.Header.Set("Content-Encoding", tc.encoding)
				}
				resp, err := client.Do(req)
				if want == 0 { // the connection is closed without an answer: the application died part way through it
					if err == nil {
						resp.Body.Close()
						t.Fatalf("status %d, want the connection closed without an answer", resp.StatusCode)
					}
					select {
					case <-requests:
					default:
						t.Fatal("the request did not reach the application")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != want {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("status %d, want %d\n%s", resp.StatusCode, want, data)
				}
				if want == 429 && (resp.Header.Get("Retry-After") != "60" || resp.Header.Get("Cache-Control") != "no-store") {
					t.Fatal("rate refusal lacks retry or cache policy")
				}
				originRequests := requests
				if tc.originAuth != "" {
					originRequests = originCalls
				}
				select {
				case got := <-originRequests:
					if want != 200 {
						t.Fatal("refused request reached the origin")
					}
					want := tc.body
					if tc.originBody != "" {
						want = tc.originBody
					}
					if got.body != want || got.encoding != "" || got.length != int64(len(want)) {
						t.Fatalf("origin received %d body bytes, encoding %q, length %d", len(got.body), got.encoding, got.length)
					}
					if got.target != requestTarget {
						t.Fatal("origin request target changed")
					}
				default:
					if want == 200 {
						t.Fatal("accepted request did not reach the origin")
					}
				}
			}
			if tc.statsRule != 0 {
				deadline := time.Now().Add(2 * time.Second)
				for {
					data, err := os.ReadFile(logPath)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, line := range bytes.Split(data, []byte("\n")) {
						var event struct {
							Msg   string
							Rules []struct {
								Rule               int
								Blocked, Monitored uint64
							}
						}
						if json.Unmarshal(line, &event) != nil || event.Msg != "format protection totals" {
							continue
						}
						for _, r := range event.Rules {
							found = found || r.Rule == tc.statsRule && r.Blocked == tc.statsBlocked && r.Monitored == tc.statsMonitored
						}
					}
					if found {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("compiled firewall did not report expected bypass totals")
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			cancel()
			_ = cmd.Wait()
			waited = true
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if tc.logRule != "" && !bytes.Contains(data, []byte(tc.logRule)) {
				t.Fatalf("expected finding %s absent from logs", tc.logRule)
			}
			if tc.says != "" && !bytes.Contains(data, []byte(tc.says)) {
				t.Fatalf("the log does not say %q:\n%s", tc.says, data)
			}
			if tc.logRule != "" {
				var wanted struct{ Rule int }
				if err := json.Unmarshal([]byte("{"+tc.logRule+"}"), &wanted); err != nil {
					t.Fatal(err)
				}
				blocked := tc.status >= 400
				if len(tc.statuses) > 0 {
					blocked = tc.statuses[len(tc.statuses)-1] >= 400
				}
				for _, id := range append([]int{wanted.Rule}, tc.alsoRules...) {
					matches := 0
					for _, line := range bytes.Split(data, []byte("\n")) {
						var event struct {
							Msg        string
							Rule       int
							Disruptive bool
						}
						if json.Unmarshal(line, &event) == nil && event.Msg == "rule matched" && event.Rule == id {
							matches++
							if event.Disruptive != blocked {
								t.Fatal("finding logged with incorrect enforcement outcome")
							}
						}
					}
					if matches < max(tc.repeat, 1) {
						t.Fatalf("not every attempt produced detection %d", id)
					}
				}
			}
			if bytes.Contains(data, []byte("SECRET_TOKEN_CLI_TEST")) {
				t.Fatal("default log disclosed request content")
			}
		})
	}
}

type statsWriter struct {
	bytes.Buffer
	emitted chan struct{}
}

func (w *statsWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	select {
	case w.emitted <- struct{}{}:
	default:
	}
	return n, err
}

func TestFormatStatsLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		periodic bool
		off      bool
		want     int
	}{
		{"graceful final snapshot", time.Hour, false, false, 1},
		{"unchanged final snapshot suppressed", 100 * time.Millisecond, true, false, 1},
		{"statistics disabled", 0, false, false, 0},
		{"formats disabled", 100 * time.Millisecond, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := formats.New(formats.Policy{Monitor: true})
			in.Inspect(&inspect.Request{Method: "HEAD", Path: "/graphql", RawQuery: "query=mutation%7BSECRET_TOKEN_CLI_TEST%7D"})
			if tc.off {
				in = nil
			}
			out := &statsWriter{emitted: make(chan struct{}, 1)}
			stop := startFormatStats(slog.New(slog.NewJSONHandler(out, nil)), in, tc.interval)
			defer stop()
			if tc.periodic {
				select {
				case <-out.emitted:
				case <-time.After(2 * time.Second):
					t.Fatal("periodic statistics were not emitted")
				}
			}
			stop() // joins the writer before reading the buffer
			if got := bytes.Count(out.Bytes(), []byte("format protection totals")); got != tc.want {
				t.Fatalf("%d snapshots, want %d", got, tc.want)
			}
			if bytes.Contains(out.Bytes(), []byte("SECRET_TOKEN_CLI_TEST")) {
				t.Fatal("statistics expose request content")
			}
			if tc.want != 0 && !bytes.Contains(out.Bytes(), []byte("\"monitored\":1")) {
				t.Fatal("final snapshot lost the finding")
			}
		})
	}
}

// The visitor's key and the CrowdSec bouncer key are read like the origin's: a key others can read is refused, and a FIFO
// put where the file was expected does not hold start-up.
// The settings a site file stores encrypted stay out of the errors the proxy prints. Given as flags, the same mistakes name
// them: that control shows each row would see a leak.
func TestEncryptedSiteSettingsStayOutOfErrors(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "site.key")
	key := make([]byte, 32)
	if _, err := cryptorand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := writeNewSiteFile(keyPath, key); err != nil {
		t.Fatal(err)
	}
	id, err := newSiteKeyID()
	if err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(dir, "hidden-place")
	for _, tc := range []struct {
		name     string
		settings map[string]string
		extra    []string
		secrets  []string
	}{
		{name: "an upstream that does not parse", settings: map[string]string{"upstream": "http://secret-origin.test:8080/%zz"},
			secrets: []string{"secret-origin"}},
		{name: "an origin range that does not parse", settings: map[string]string{"upstream": "http://192.0.2.80:8080", "origin-allow": "192.0.2.0/24,10.99.88.0/33"},
			secrets: []string{"10.99.88", "192.0.2"}},
		{name: "a certificate that is not there", settings: map[string]string{"upstream": "http://192.0.2.80:8080", "origin-allow": "192.0.2.0/24",
			"tls-cert": filepath.Join(hidden, "site-cert.pem"), "tls-key": filepath.Join(hidden, "site-key.pem")}, secrets: []string{"hidden-place", "192.0.2"}},
		{name: "an origin that refuses the check", settings: map[string]string{"upstream": "http://127.0.0.1:1", "origin-allow": "127.0.0.0/8"},
			extra: []string{"-check-origin"}, secrets: []string{"127.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]any{}
			var asFlags []string
			for name, value := range tc.settings {
				settings[name] = value
				asFlags = append(asFlags, "-"+name, value)
			}
			sealed, err := sealSiteSettings(settings, id, key)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(siteDocument{Version: 1, Flags: map[string]any{}, Private: sealed})
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(t.TempDir(), "site.json")
			if err := os.WriteFile(config, data, 0600); err != nil {
				t.Fatal(err)
			}
			named := func(err error) bool {
				for _, secret := range tc.secrets {
					if strings.Contains(err.Error(), secret) {
						return true
					}
				}
				return false
			}
			err = runArgs(append([]string{"-config", config, "-config-key-file", keyPath, "-check"}, tc.extra...))
			if err == nil {
				t.Fatal("the mistake was not reported")
			}
			if named(err) {
				t.Errorf("the error names an encrypted setting: %v", err)
			}
			if err = runArgs(append(append(asFlags, "-check"), tc.extra...)); err == nil || !named(err) {
				t.Errorf("control: given as flags, the error does not name the setting: %v", err)
			}
		})
	}
}

func TestPrivateSettingsAreLeftOutOfErrorText(t *testing.T) {
	private := map[string]string{"upstream": "http://origin:8080/x", "origin-allow": "10.0.0.0/8,10.99.88.0/33",
		"tls-key": `C:\keys\site.key`, "upstream-host": "shop.example.test"}
	for _, tc := range []struct{ name, in, want string }{
		{"a URL in a parse error", `parse "http://origin:8080/x": invalid URL escape "%zz"`, `parse "[private setting]": invalid URL escape "%zz"`},
		{"one entry of a list", `invalid origin range "10.99.88.0/33"`, `invalid origin range "[private setting]"`},
		{"a path", `open C:\keys\site.key: not found`, `open [private setting]: not found`},
		{"an address the origin resolved to", `dial tcp 10.1.2.3:8080: refused`, `dial tcp [address]: refused`},
		{"a one-word host is replaced only where it can be nothing else", `origin preflight: lookup origin: no such host`,
			`origin preflight: lookup [private setting]: no such host`},
		{"a longer name is left alone", `shop.example.testing and shop.example.test.`, `shop.example.testing and [private setting].`},
		{"nothing private", `-listen must have a valid TCP port`, `-listen must have a valid TCP port`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := redactPrivate(errors.New(tc.in), private)
			if err.Error() != tc.want {
				t.Fatalf("%q, want %q", err.Error(), tc.want)
			}
		})
	}
	if err := redactPrivate(fmt.Errorf("at http://origin:8080/x: %w", flag.ErrHelp), private); !errors.Is(err, flag.ErrHelp) ||
		strings.Contains(err.Error(), "origin:8080") {
		t.Fatalf("a redacted error no longer unwraps to what it was, or kept the setting: %v", err)
	}
}

func TestPrivateFilesAreReadWithCare(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	private, open := write("private.key", 0o600), write("open.key", 0o644)
	groupRead, groupWrite := write("group.key", 0o640), write("groupwrite.key", 0o620)
	readers := map[string]func(string, bool) error{
		"visitor TLS": func(p string, priv bool) error { _, err := readTLSFile(p, 64<<10, priv); return err },
		"CrowdSec":    func(p string, priv bool) error { _, err := readCrowdSecFile(p, 4096, priv); return err },
		"origin":      func(p string, priv bool) error { _, err := readOriginFile(p, 64<<10, priv); return err },
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			if err := read(private, true); err != nil {
				t.Fatalf("a private key: %v", err)
			}
			if err := read(groupRead, true); err != nil {
				t.Fatalf("a key its group may read: %v", err)
			}
			if err := read(open, false); err != nil {
				t.Fatalf("a public file: %v", err)
			}
			if err := read(open, true); runtime.GOOS != "windows" && err == nil {
				t.Fatal("a key everyone can read was accepted")
			}
			if err := read(groupWrite, true); runtime.GOOS != "windows" && err == nil {
				t.Fatal("a key its group may write was accepted")
			}
			if err := read(dir, false); err == nil {
				t.Fatal("a directory was read")
			}
			if runtime.GOOS == "windows" {
				return
			}
			fifo := filepath.Join(t.TempDir(), "fifo.key")
			if err := exec.Command("mkfifo", "-m", "0600", fifo).Run(); err != nil {
				t.Skipf("no FIFO here: %v", err)
			}
			for _, priv := range []bool{false, true} { // a mode the key check accepts, so only the file type can refuse it
				done := make(chan error, 1)
				go func() { done <- read(fifo, priv) }()
				select {
				case err := <-done:
					if err == nil {
						t.Fatalf("a FIFO was read (private %v)", priv)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("reading a FIFO blocked")
				}
			}
		})
	}
	t.Run("visitor TLS through a link", func(t *testing.T) {
		// certbot's live/ directory holds links into archive/; the visitor's pair is read through them.
		link := filepath.Join(t.TempDir(), "privkey.pem")
		if err := os.Symlink(private, link); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		if _, err := readTLSFile(link, 64<<10, true); err != nil {
			t.Fatalf("a key through a link: %v", err)
		}
	})
}

// TestUploadDirIsCheckedBeforeConfinement: the confined proxy can write only its upload directory, which Landlock can grant
// only if it exists, and which must not be open to other users.
func TestUploadDirIsCheckedBeforeConfinement(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unix := runtime.GOOS != "windows" // Windows has no such mode bits
	for _, tt := range []struct {
		name string
		path string
		ok   bool
	}{
		{"its own directory", mk("own", 0o700), true},
		{"readable by others", mk("readable", 0o755), true},
		{"not there", filepath.Join(dir, "missing"), false},
		{"a file", file, false},
		{"writable by its group", mk("group", 0o770), !unix},
		{"writable by everyone", mk("everyone", 0o777), !unix},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkUploadDir(tt.path); (err == nil) != tt.ok {
				t.Fatalf("accepted %v, want %v: %v", err == nil, tt.ok, err)
			}
		})
	}
}

// net/http's own lines about connections reach the JSON log without the client's address, unless details are on, and at most
// one a second.
func TestServerErrorsAreLoggedWithoutAddresses(t *testing.T) {
	type entry struct {
		Msg, Kind, Error string
		Dropped          int
		CutBytes         int `json:"cut_bytes"`
	}
	logged := func(t *testing.T, out *bytes.Buffer) []entry {
		t.Helper()
		var got []entry
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var e entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("not JSON (%v): %s", err, line)
			}
			got = append(got, e)
		}
		return got
	}
	write := func(t *testing.T, s *serverErrors, line string) {
		t.Helper()
		if n, err := s.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatalf("Write took %d of %d bytes: %v", n, len(line), err)
		}
	}
	at := func(out *bytes.Buffer, details bool, now func() time.Time) *serverErrors {
		return &serverErrors{log: slog.New(slog.NewJSONHandler(out, nil)), details: details, now: now}
	}
	for _, tt := range []struct {
		name    string
		details bool
		line    string
		want    string
	}{
		{"IPv4 handshake", false, "http: TLS handshake error from 192.0.2.7:51234: EOF\n", "http: TLS handshake error from [address]: EOF"},
		// What the client sent is quoted in the line; it is left out, and it cannot pass the line off as a panic.
		{"protocols the client asked for", false, "http: TLS handshake error from 192.0.2.7:51234: tls: client requested unsupported application protocols ([\"panic serving\" \"x\\\"y\"])\n",
			"http: TLS handshake error from [address]: tls: client requested unsupported application protocols ([\"[client data]\" \"[client data]\"])"},
		{"a greeting that was not HTTP/2", false, "http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"Accept error: 1.2.3.4:56\"\n",
			"http2: server: error reading preface from client [address]: bogus greeting \"[client data]\""},
		{"IPv6 preface", false, "http2: server: error reading preface from client [2001:db8::7]:443: bogus greeting\n", "http2: server: error reading preface from client [address]: bogus greeting"},
		{"both ends of a timed-out connection", false, "http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout\n",
			"http: TLS handshake error from [address]: read tcp [address]->[address]: i/o timeout"},
		{"both ends with IPv6 zones", false, "http2: server: error reading preface from client [fe80::1%eth0]:51234: read tcp [fe80::2%eth0]:443->[fe80::1%eth0]:51234: read: connection reset by peer\n",
			"http2: server: error reading preface from client [address]: read tcp [address]->[address]: read: connection reset by peer"},
		{"an address without a port", false, "http: TLS handshake error from 192.0.2.7:51234: lookup example.com on 2001:db8::53: no such host\n",
			"http: TLS handshake error from [address]: lookup example.com on [address]: no such host"},
		{"an IPv6 address that ends in a colon", false, "httputil: ReverseProxy read error during body copy: dial 2001:db8:: refused\n",
			"httputil: ReverseProxy read error during body copy: dial [address] refused"},
		{"an IPv6 address that ends a clause", false, "lookup example.com on 2001:db8::: no such host\n", "lookup example.com on [address]: no such host"},
		{"a line with no address", false, "http: superfluous response.WriteHeader call from main.handler (main.go:12)\n", "http: superfluous response.WriteHeader call from main.handler (main.go:12)"},
		{"details keep it", true, "http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout\n",
			"http: TLS handshake error from 127.0.0.1:61492: read tcp 127.0.0.1:61491->127.0.0.1:61492: i/o timeout"},
		{"details keep what the client sent", true, "http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"PRI\"\n",
			"http2: server: error reading preface from client 192.0.2.7:51234: bogus greeting \"PRI\""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			now := time.Unix(1000, 0)
			s := at(&out, tt.details, func() time.Time { return now })
			write(t, s, tt.line)
			write(t, s, tt.line) // the same second: counted, not logged
			now = now.Add(time.Second)
			write(t, s, tt.line)
			got := logged(t, &out)
			if len(got) != 2 || got[0].Error != tt.want || got[1].Error != tt.want || got[0].Kind != "connection" {
				t.Fatalf("logged %+v, want twice %q", got, tt.want)
			}
			if got[0].Dropped != 0 || got[1].Dropped != 1 {
				t.Fatalf("the line dropped in the first second was not counted: %+v", got)
			}
		})
	}
	t.Run("each kind of line has its own second", func(t *testing.T) {
		// A flood of handshake errors must not hide a handler's panic or a failing accept, even one that names them.
		var out bytes.Buffer
		s := at(&out, false, func() time.Time { return time.Unix(1000, 0) })
		const handshake = "http: TLS handshake error from 192.0.2.7:51234: EOF\n"
		const named = "http: TLS handshake error from 192.0.2.7:51234: tls: client requested unsupported application protocols ([\"panic serving\"])\n"
		for _, line := range []string{handshake, named, "http: panic serving 192.0.2.7:51234: boom\ngoroutine 7 [running]:\n",
			"http: Accept error: accept tcp [::]:443: accept4: too many open files; retrying in 5ms\n", named, handshake} {
			write(t, s, line)
		}
		s.flush() // as the server stops: what was counted is reported
		got := logged(t, &out)
		want := []entry{
			{"server error", "connection", "http: TLS handshake error from [address]: EOF", 0, 0},
			{"server error", "panic", "http: panic serving [address]: boom\ngoroutine 7 [running]:", 0, 0},
			{"server error", "accept", "http: Accept error: accept tcp [address]: accept4: too many open files; retrying in 5ms", 0, 0},
			{"server errors not logged", "connection", "", 3, 0},
		}
		if !slices.Equal(got, want) {
			t.Fatalf("logged %+v\nwant   %+v", got, want)
		}
	})
	t.Run("a long line is cut after its addresses are hidden", func(t *testing.T) {
		for _, tt := range []struct {
			line, start string
			limit       int
		}{
			// The cut falls inside a two-byte character, so it must move back to where the character starts.
			{"http: TLS handshake error from 192.0.2.7:51234: x" + strings.Repeat("é", 2000) + "\n", "http: TLS handshake error from [address]: xé", maxErrorLine - 1},
			{"http: panic serving 192.0.2.7:51234: boom\n" + strings.Repeat("main.handler(...)\n", 2000), "http: panic serving [address]: boom\nmain.handler", maxPanicLine},
		} {
			var out bytes.Buffer
			write(t, at(&out, false, time.Now), tt.line)
			got := logged(t, &out)
			if len(got) != 1 || len(got[0].Error) != tt.limit || !strings.HasPrefix(got[0].Error, tt.start) || !utf8.ValidString(got[0].Error) ||
				strings.ContainsRune(got[0].Error, utf8.RuneError) || got[0].CutBytes == 0 {
				t.Fatalf("logged %d bytes (cut %d), want %d starting %q", len(got[0].Error), got[0].CutBytes, tt.limit, tt.start)
			}
		}
	})
}

// TestBothServersLogTheirOwnErrorsAsJSON: what net/http says about the visitor and health servers (here an accept that
// failed for a while, as when descriptors run out) reaches the JSON log, not standard error.
func TestBothServersLogTheirOwnErrorsAsJSON(t *testing.T) {
	for _, failing := range []string{"visitor", "health"} {
		t.Run(failing, func(t *testing.T) {
			var out syncBuffer
			listen := func() net.Listener {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				return ln
			}
			visitor, health := listen(), listen()
			flaky := &failingListener{fails: 2, retried: make(chan struct{})}
			if failing == "visitor" {
				flaky.Listener, visitor = visitor, flaky
			} else {
				flaky.Listener, health = health, flaky
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
			done := make(chan error, 1)
			go func() {
				done <- serveRuntime(ctx, server, visitor, health, &runtimeHealth{}, lifecycleOptions{shutdown: time.Second},
					slog.New(slog.NewJSONHandler(&out, nil)))
			}()
			select {
			case <-flaky.retried: // net/http logs the failure before it tries again
			case <-time.After(10 * time.Second):
				t.Fatal("the server never tried again")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// Each failure is in the log: as a line of its own, or counted by a later line or when the server stopped (the
			// second comes 5ms after the first, so it is nearly always held back to be reported then).
			logged, accounted := 0, 0
			for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				var e struct {
					Msg, Server, Kind, Error string
					Dropped                  int
				}
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatalf("not JSON (%v): %s", err, line)
				}
				switch {
				case e.Server != failing || e.Kind != "accept":
				case e.Msg == "server error" && strings.HasPrefix(e.Error, "http: Accept error: accept failed for a while; retrying"):
					logged++
					accounted += 1 + e.Dropped
				case e.Msg == "server errors not logged":
					accounted += e.Dropped
				}
			}
			if logged == 0 || accounted != flaky.fails {
				t.Fatalf("the %s server's %d failures: %d logged, %d accounted for:\n%s", failing, flaky.fails, logged, accounted, out.String())
			}
		})
	}
}

// failingListener fails its first Accepts with an error net/http logs and retries, and says when it is asked again.
type failingListener struct {
	net.Listener
	fails   int
	calls   atomic.Int32
	retried chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	switch n := int(l.calls.Add(1)); {
	case n <= l.fails:
		return nil, temporaryAcceptError{}
	case n == l.fails+1:
		close(l.retried)
	}
	return l.Listener.Accept()
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "accept failed for a while" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

// syncBuffer is a bytes.Buffer two servers can write at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
