package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

/*
TestMainHelper is a special helper test that is run in a subprocess. The pattern is:

  - The parent test process runs `go test` as usual.
  - Individual tests that want to exercise main() start a CHILD test process
    using `exec.Command(os.Args[0], "-test.run=TestMainHelper", "--", args...)`
    and set an env var `TEST_MAIN_HELPER=1`.
  - Inside the child process, TestMainHelper sees the env var, strips out the
    program arguments after "--", rewrites os.Args accordingly, and calls main().

This lets us:
  - Run main() with arbitrary CLI flags.
  - Observe its exit code (log.Fatalf → os.Exit(1)).
  - Avoid hanging the parent test process, because the child is killable / isolated.

When TEST_MAIN_HELPER is NOT set, this function returns immediately, so in the
normal test run it is just a no-op test.
*/
func TestMainHelper(t *testing.T) {
	if os.Getenv("TEST_MAIN_HELPER") != "1" {
		return
	}
	// Extract args after "--" and turn them into os.Args for main().
	args := []string{}
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) > 0 {
		os.Args = append([]string{os.Args[0]}, args...)
	} else {
		os.Args = []string{os.Args[0]}
	}
	// Call the real main().
	main()
	// If main() returns normally, exit with code 0.
	os.Exit(0)
}

/*
runMain runs main() in a CHILD test process with the given CLI args and returns:

  - exitCode: the child's exit code (log.Fatalf typically → non-zero).
  - stderr: any stderr output from the child (where log prints).

The parent process never calls main() directly; instead, it uses this helper
to drive and inspect main()'s behavior.
*/
func runMain(t *testing.T, args ...string) (exitCode int, stderr string) {
	t.Helper()

	cmdArgs := []string{"-test.run=TestMainHelper", "--"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "TEST_MAIN_HELPER=1")

	var stderrBuf bytes.Buffer
	cmd.Stdout = &bytes.Buffer{} // ignore stdout
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err == nil {
		// main() exited with code 0
		return 0, stderrBuf.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), stderrBuf.String()
	}
	t.Fatalf("runMain: unexpected error: %v", err)
	return 0, stderrBuf.String()
}

/*
runMainUntilKilled starts main() in a CHILD process (like runMain), waits for
a short duration, then kills it.

This is used to exercise the “happy path” of main (where it would normally run
forever) long enough to execute the initial setup code:
  - TLS config creation,
  - directory creation,
  - DirStore setup,
  - listener creation, etc.

We don't care about the exit code here; we just want to ensure main() starts
without immediately fatalling in that configuration.
*/
func runMainUntilKilled(t *testing.T, wait time.Duration, args ...string) (stderr string) {
	t.Helper()

	cmdArgs := []string{"-test.run=TestMainHelper", "--"}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "TEST_MAIN_HELPER=1")

	var stderrBuf bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("runMainUntilKilled: start: %v", err)
	}

	// Give the child time to set up listeners, goroutines, etc.
	time.Sleep(wait)

	// Kill the process; it would otherwise run forever.
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	return stderrBuf.String()
}

/*
generateSelfSignedCert generates a throwaway self-signed certificate and key,
writes them to PEM files in the given directory, and returns their paths.

This is used to exercise the TLS-success path in main() without requiring real
certificates on disk.
*/
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	// Private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Minimal self-signed certificate template.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// Write cert PEM.
	certPath = filepath.Join(dir, "server.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("pem.Encode cert: %v", err)
	}
	_ = certOut.Close()

	// Write key PEM.
	keyPath = filepath.Join(dir, "server.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("pem.Encode key: %v", err)
	}
	_ = keyOut.Close()

	return certPath, keyPath
}

/*
TestMain_TLSRequestedWithoutKeys verifies the earliest TLS guard:

  - If StartTLS is enabled OR LDAPS is configured,
  - AND either tls-cert or tls-key is missing (empty),
  - Then main() must call log.Fatalf("TLS requested but -tls-cert and -tls-key not both provided")
    and exit with a non-zero code.

We simulate this by:
  - Setting -data= (empty) so JSON load is skipped and the built-in directory
    would be used (if we got that far).
  - Leaving ldapsAddr at its default non-empty value.
  - Passing -tls-cert= and -tls-key= to force empty paths.

The expected behavior is an immediate fatal before any directory loading.
*/
func TestMain_TLSRequestedWithoutKeys(t *testing.T) {
	exitCode, stderr := runMain(t,
		"-data=",
		"-tls-cert=",
		"-tls-key=",
	)

	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code when TLS requested but no keys")
	}
	if !strings.Contains(stderr, "TLS requested but -tls-cert and -tls-key not both provided") {
		t.Fatalf("expected TLS error in stderr, got:\n%s", stderr)
	}
}

/*
TestMain_JSONLoadError verifies the JSON loading error path:

  - When -data points to a non-existent JSON file,
  - And TLS is not required (StartTLS disabled, no LDAPS),
  - main() should call log.Fatalf("load JSON: ...") and exit with non-zero.

We ensure the TLS guard does NOT fire by:
  - Passing -starttls=false and -ldaps= (empty),
  - And also clearing cert/key paths to avoid attempting TLS setup.
*/
func TestMain_JSONLoadError(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does_not_exist.json")

	exitCode, stderr := runMain(t,
		"-data="+missing,
		"-starttls=false",
		"-ldaps=",
		"-tls-cert=",
		"-tls-key=",
		"-http=", // disable HTTP so we don't hit its TLS requirement
	)

	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for JSON load failure")
	}
	if !strings.Contains(stderr, "load JSON") {
		t.Fatalf("expected 'load JSON' in stderr, got:\n%s", stderr)
	}
}

/*
TestMain_TLSCertLoadError verifies the TLS certificate loading path:

  - When StartTLS/LDAPS are requested AND both tls-cert and tls-key are
    non-empty but invalid paths,
  - main() should attempt tls.LoadX509KeyPair and fail with
    log.Fatalf("load TLS cert/key: ...").

We simulate this by:
  - Setting -data= so we would use the built-in directory.
  - Leaving defaults for StartTLS and LDAPS (both "requested").
  - Passing bogus non-empty tls-cert/tls-key paths.
*/
func TestMain_TLSCertLoadError(t *testing.T) {
	tmp := t.TempDir()
	missingCert := filepath.Join(tmp, "missing.crt")
	missingKey := filepath.Join(tmp, "missing.key")

	exitCode, stderr := runMain(t,
		"-data=",
		"-tls-cert="+missingCert,
		"-tls-key="+missingKey,
	)

	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for TLS cert/key load failure")
	}
	if !strings.Contains(stderr, "load TLS cert/key") {
		t.Fatalf("expected 'load TLS cert/key' in stderr, got:\n%s", stderr)
	}
}

/*
TestMain_HTTPAPIRequiresTLS verifies the HTTP API TLS requirement:

  - If -data is non-empty (we have a JSON config file),
  - And -http is non-empty (we want HTTPS API),
  - BUT tlsConf is nil because no tls-cert/tls-key are provided and the initial
    TLS guard is skipped,
  - Then main() should fatal with
    "HTTPS API requested (-http ...) but no TLS config available".

We ensure the initial TLS guard is skipped by:
  - Setting -starttls=false and -ldaps= (so (enableStartTLS || ldapsAddr != "") == false).
  - Passing -tls-cert= and -tls-key=.

We also write a minimal valid JSON config (just BaseDN) to satisfy
LoadDirectoryFromJSON.
*/
func TestMain_HTTPAPIRequiresTLS(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.json")
	json := `{"BaseDN":"dc=example,dc=com"}`
	if err := os.WriteFile(cfgPath, []byte(json), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", cfgPath, err)
	}

	exitCode, stderr := runMain(t,
		"-data="+cfgPath,
		"-http=127.0.0.1:0",
		"-starttls=false",
		"-ldaps=",
		"-tls-cert=",
		"-tls-key=",
	)

	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code when HTTP API requested without TLS config")
	}
	if !strings.Contains(stderr, "TLS requested") {
		t.Fatalf("expected 'TLS requested' error in stderr, got:\n%s", stderr)
	}
}

/*
TestMain_NoData_UsesBuiltInDirectory verifies the "built-in example directory"
branch when -data is empty:

  - dataPath == "" should skip LoadDirectoryFromJSON and instead construct
    a default in-memory directory rooted at dc=homelab,dc=lan with a seeded
    user and admin group.
  - We also configure valid TLS cert/key so the initial TLS guard passes and
    tlsConf is constructed.
  - We use -listen=127.0.0.1:0 to bind to an ephemeral port, and disable LDAPS
    to avoid extra listeners.

Because the happy path runs forever, we don't try to observe final behavior.
Instead, we:
  - Start main() in a child process with this configuration.
  - Sleep briefly to allow it to run through initial setup (building dir,
    DirStore, listeners, goroutines).
  - Kill the child.

If main() had failed early (e.g. by fatalling in this configuration), the
child would have exited before we killed it, and stderr would contain
an error. We assert that NO obvious fatal prefix is present.
*/
func TestMain_NoData_UsesBuiltInDirectory(t *testing.T) {
	tmp := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, tmp)

	stderr := runMainUntilKilled(t, 200*time.Millisecond,
		"-data=",              // force built-in example directory
		"-tls-cert="+certPath, // valid cert/key so TLS setup succeeds
		"-tls-key="+keyPath,
		"-starttls=false",     // don't require StartTLS
		"-ldaps=",             // disable LDAPS
		"-listen=127.0.0.1:0", // ephemeral LDAP port
		"-http=",              // no HTTP API
	)

	// We don't expect a fatal log; at minimum, we can assert that the very
	// specific strings from known fatal paths are not present.
	if strings.Contains(stderr, "TLS requested but -tls-cert and -tls-key not both provided") {
		t.Fatalf("unexpected TLS config fatal in stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "load JSON") {
		t.Fatalf("unexpected JSON load fatal in stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "HTTPS API requested") {
		t.Fatalf("unexpected HTTP API TLS fatal in stderr:\n%s", stderr)
	}
}

/*
TestMain_CanCreateTLSConfigAlone is a small sanity check that our generated
self-signed certificates are suitable for tls.LoadX509KeyPair.

Although this doesn't call main(), it indirectly validates that the TLS
paths we exercise in other tests are realistic and can succeed when used
in a non-error configuration.
*/
func TestMain_CanCreateTLSConfigAlone(t *testing.T) {
	tmp := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, tmp)

	_, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("tls.LoadX509KeyPair failed on generated cert/key: %v", err)
	}
	fmt.Println("tls.LoadX509KeyPair succeeded on generated self-signed cert")
}
