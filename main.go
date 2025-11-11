package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"jldap/directory"
	"jldap/json_config"
	"jldap/ldap"
	"jldap/web"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	/*
		Sets logging flags to include:
			Ldate, Ltime, Lmicroseconds – detailed timestamp.
			Llongfile – full file path and line number in log messages.
			LUTC – use UTC time.
			Lmsgprefix – treat the log prefix as a prefix, not part of the message.
		So logs are very detailed and timestamped.
	*/
	log.SetFlags(log.LstdFlags | log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile | log.LUTC | log.Lmsgprefix)

	// Declares variables that will hold values from command line flags.
	var dataPath string
	var listenAddr string
	var ldapsAddr string
	var enableStartTLS bool
	var certPath string
	var keyPath string
	var httpAddr string
	// Defines CLI flags:
	// -data – JSON file with baseDN, users, groups, default jldap.json.
	flag.StringVar(&dataPath, "data", "jldap.json", "path to JSON file with baseDN, users, groups (e.g, jldap.json")
	// -listen – plain LDAP address, default 0.0.0.0:1389.
	flag.StringVar(&listenAddr, "listen", "0.0.0.0:1389", "LDAP address to listen on (e.g., 0.0.0.0:1389)")
	// -ldaps – LDAPS (LDAP over TLS) address, default 0.0.0.0:1636.
	flag.StringVar(&ldapsAddr, "ldaps", "0.0.0.0:1636", "LDAPS address to listen on (e.g., 0.0.0.0:1636)")
	// -starttls – enable StartTLS on the plain LDAP listener, default true.
	flag.BoolVar(&enableStartTLS, "starttls", true, "Enable StartTLS on the plain LDAP listener (requires -tls-cert/-tls-key)")
	// -tls-cert, -tls-key – paths to TLS cert and key files, default server.crt, server.key.
	flag.StringVar(&certPath, "tls-cert", "server.crt", "TLS certificate PEM (required for StartTLS/LDAPS)")
	flag.StringVar(&keyPath, "tls-key", "server.key", "TLS private key PEM (required for StartTLS/LDAPS)")
	// -http – HTTPS REST/UI API address, default 0.0.0.0:8443.
	flag.StringVar(&httpAddr, "http", "0.0.0.0:8443", "HTTPS API address for POST/DELETE users/groups")
	// flag.Parse() parses os.Args into these variables.
	flag.Parse()
	// TLS configuration starts as nil.
	var tlsConf *tls.Config
	// If either: StartTLS is enabled, OR LDAPS address is non-empty, OR the HTTPS API address is non empty, and either cert or key is missing: It’s an invalid configuration ⇒ crash with a fatal log.
	if (enableStartTLS || ldapsAddr != "" || httpAddr != "") && (certPath == "" || keyPath == "") {
		log.Fatalf("TLS requested but -tls-cert and -tls-key not both provided")
	}
	// If cert and key paths are both non-empty: Load the X.509 certificate + key.
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		// On error, fatal and exit.
		if err != nil {
			log.Fatalf("load TLS cert/key: %+v", err)
		}
		// Else create a tls.Config with: the loaded certificate, and MinVersion = TLS 1.2, so older versions are rejected.
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	// Now tlsConf is either nil (no TLS) or properly configured.
	// Directory loading - dir will be the in-memory LDAP directory.
	var dir *directory.Directory
	var err error
	// If -data is provided (non-empty), load the directory from the JSON file using json_config.LoadDirectoryFromJSON.
	if dataPath != "" {
		dir, err = json_config.LoadDirectoryFromJSON(dataPath)
		// On error ⇒ fatal.
		if err != nil {
			log.Fatalf("load JSON: %+v", err)
		}
	} else {
		// If no -data argument: Log that a built-in example directory will be used.
		log.Printf("no -data provided; using built-in example")
		// Create a new in-memory directory rooted at dc=homelab,dc=lan.
		dir = directory.NewDirectory("dc=homelab,dc=lan")
		// Seed example user entry with typical LDAP + posix account fields.
		dir.Add(&directory.Entry{
			DN: "uid=jbennet,ou=users,dc=homelab,dc=lan",
			Attrs: map[string][]string{
				"objectclass":   {"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"},
				"cn":            {"James Bennet"},
				"sn":            {"Bennet"},
				"givenname":     {"James"},
				"displayname":   {"James Bennet"},
				"uid":           {"jbennet"},
				"mail":          {"james.bennet@homelab.lan"},
				"userpassword":  {"password1234"},
				"uidnumber":     {"1001"},
				"gidnumber":     {"2001"},
				"homedirectory": {"/home/jbennet"},
				"loginshell":    {"/bin/bash"},
			},
			Parent: "ou=users,dc=homelab,dc=lan",
		})
		// Seed example admin group containing that user.
		dir.Add(&directory.Entry{
			DN: "cn=homelab_admins,ou=groups,dc=homelab,dc=lan",
			Attrs: map[string][]string{
				"objectclass": {"top", "posixGroup", "groupOfNames"},
				"cn":          {"homelab_admins"},
				"gidnumber":   {"2001"},
				"memberuid":   {"jbennet"},
				"member":      {"uid=jbennet,ou=users,dc=homelab,dc=lan"},
			},
			Parent: "ou=groups,dc=homelab,dc=lan",
		})
	}
	// Create a DirStore, which wraps a *Directory in an atomic.Value for concurrent access.
	store := &directory.DirStore{}
	// Set the current directory snapshot in the store.
	store.Set(dir)
	// Config store / HTTP API - cfg will hold the JSON config store if HTTP API is enabled.
	var cfg *json_config.ConfigStore
	/*
		HTTP API runs only if: dataPath is non-empty (needs a config file), and httpAddr is non-empty (wants an HTTPS API).
		If so, but tlsConf is nil ⇒ cannot serve HTTPS ⇒ fatal with message.
		Otherwise, start HTTPS API via web.StartHTTPAPI, passing: HTTP address, Path to JSON config, Directory store, TLS config.
		StartHTTPAPI starts its own goroutine and returns a *ConfigStore.
	*/
	// SIGHUP triggered reload + periodic auto-reload
	if dataPath != "" && httpAddr != "" {
		if tlsConf == nil {
			log.Fatalf("HTTPS API requested (-http %s) but no TLS config available; provide -tls-cert and -tls-key", httpAddr)
		}
		cfg = web.StartHTTPAPI(httpAddr, dataPath, store, tlsConf)
	}
	if dataPath != "" {
		// If a data file is in use, set up reload mechanisms.
		// Create a buffered channel sigc for OS signals.
		sigc := make(chan os.Signal, 1)
		// Register for SIGHUP signals.
		signal.Notify(sigc, syscall.SIGHUP)
		// Start a goroutine that loops on sigc.
		go func() {
			// Every time a SIGHUP is received, log that reloading is starting.
			for range sigc {
				log.Printf("SIGHUP received: reloading %s ...", dataPath)
				// Reload the directory from the JSON file.
				newDir, err := json_config.LoadDirectoryFromJSON(dataPath)
				// If it fails, log and skip this iteration.
				if err != nil {
					log.Printf("reload failed: %+v", err)
					continue
				}
				// On success, update the DirStore so all future connections see the new directory.
				store.Set(newDir)
				// Log the new base DN.
				log.Printf("reload complete; base DN: %s", newDir.BaseDN)

				/*
					If HTTP config store is present:Reload the ConfigStore from disk.If it fails, log.
					Otherwise: Acquire write lock on config.
					Ensure AdminUsersCN is non-empty; if empty, default to "homelab_admins".
					Unlock.
				*/
				if cfg != nil {
					if err := cfg.LoadFromDisk(); err != nil {
						log.Printf("config reload failed: %+v", err)
					} else {
						cfg.Mu.Lock()
						if strings.TrimSpace(cfg.Data.AdminUsersCN) == "" {
							cfg.Data.AdminUsersCN = "homelab_admins"
						}
						cfg.Mu.Unlock()
					}
				}
			}
		}() // End of SIGHUP-handling goroutine.
		// Periodic (10-minute) auto-reload - Start another goroutine for periodic reloads.
		go func() {
			// Create a ticker that fires every 10 minutes.
			t := time.NewTicker(10 * time.Minute)
			// Ensure ticker is stopped when goroutine exits (it doesn’t, but this is correct cleanup code).
			defer t.Stop()
			// Initialize lastModTime to the file’s current modification time (if os.Stat is successful).
			var lastModTime time.Time
			if fi, err := os.Stat(dataPath); err == nil {
				lastModTime = fi.ModTime()
			}
			if err != nil {
				log.Printf("%+v", err)
			}
			for {
				// Infinite loop: waits for each tick on the ticker’s channel.
				<-t.C
				// Stat the data file again.
				fi, err := os.Stat(dataPath)
				if err != nil {
					// On error (file missing, permissions) log and skip this tick.
					log.Printf("auto-reload: periodic reload failed - cannot stat %s: %+v", dataPath, err)
					continue
				}
				// Otherwise, read new modification time.
				modTime := fi.ModTime()
				// If the file’s mod time is newer than lastModTime, then the file changed ⇒ reload.
				if modTime.After(lastModTime) {
					log.Printf("auto-reload: detected change in %s (mtime %s), reloading...", dataPath, modTime.Format(time.RFC3339))
					// Load a new directory from JSON, same as in SIGHUP handler.
					newDir, err := json_config.LoadDirectoryFromJSON(dataPath)
					if err != nil {
						log.Printf("auto-reload: reload failed: %+v", err)
						continue
					}
					// On success, update store and lastModTime, log success.
					store.Set(newDir)
					lastModTime = modTime
					log.Printf("auto-reload: periodic reload complete; base DN: %s", newDir.BaseDN)
					// Similarly reload cfg from disk and ensure AdminUsersCN is set.
					if cfg != nil {
						if err := cfg.LoadFromDisk(); err != nil {
							log.Printf("auto-reload: config reload failed: %+v", err)
						} else {
							cfg.Mu.Lock()
							if strings.TrimSpace(cfg.Data.AdminUsersCN) == "" {
								cfg.Data.AdminUsersCN = "homelab_admins"
							}
							cfg.Mu.Unlock()
						}
					}
				}
			}
		}() // End of periodic auto-reload goroutine and the if dataPath != "" block.
	}
	// Start plain LDAP (unencrypted) listener - Open a TCP listener at listenAddr (default 0.0.0.0:1389). If it fails (port in use, permission), fatal.
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen (ldap): %+v", err)
	}
	// Log that LDAP is listening, showing: address, base DN, whether StartTLS is effectively enabled (enableStartTLS flag AND tlsConf non-nil).
	log.Printf("LDAP listening on %s; base DN: %s (StartTLS: %+v)", listenAddr, dir.BaseDN, enableStartTLS && tlsConf != nil)
	// Optional LDAPS listener
	var lTLS net.Listener
	// If ldapsAddr is non-empty, we want to serve LDAPS.
	if ldapsAddr != "" {
		// If there’s no tlsConf, then we can’t ⇒ fatal.
		if tlsConf == nil {
			log.Fatalf("LDAPS requested but no TLS config available")
		}
		// Listen on ldapsAddr (default 0.0.0.0:1636).
		baseListener, err := net.Listen("tcp", ldapsAddr)
		if err != nil {
			log.Fatalf("listen (ldaps): %+v", err)
		}
		// Wrap the TCP listener with tls.NewListener to speak TLS.
		lTLS = tls.NewListener(baseListener, tlsConf)
		log.Printf("LDAPS listening on %s", ldapsAddr)
	}
	// Accept connections on plain LDAP - Start a goroutine to accept connections from l (plain LDAP).
	go func() {
		for {
			// Infinite loop: Accept() a new connection, c. If accept fails, log and continue.
			c, err := l.Accept()
			if err != nil {
				log.Printf("accept (ldap): %+v", err)
				continue
			}
			/*
					For each accepted connection: Create a new ldap.Session struct, passing:
						Conn: the TCP connection.
						Dir: the current directory pointer (dir) – initial snapshot.
						Store: the DirStore so the session can see updated directory on reload.
				If StartTLS is enabled: Attach TlsConfig so the session can handle StartTLS operations.
				Launch sess.Serve() in its own goroutine to handle the protocol, so the accept loop can keep accepting.
			*/
			sess := &ldap.Session{Conn: c, Dir: dir, Store: store}
			if enableStartTLS {
				sess.TlsConfig = tlsConf
			}
			go sess.Serve()
		}
	}()
	// Accept connections on LDAPS or block
	/*
		If lTLS is non-nil (LDAPS enabled): Run another accept loop in the main goroutine: Accept TLS (encrypted) connections.
		Wrap each connection in an ldap.Session:
			TlsConfig: TLS config (already active).
			TlsActive: true – indicates this connection is already under TLS.
		Start Serve() in a goroutine for each connection.

		Else: If there is no LDAPS listener, the main goroutine just blocks forever, as as select {} with no cases never returns, so the program stays running while other goroutines handle LDAP/HTTP and reloads.
	*/
	if lTLS != nil {
		for {
			c, err := lTLS.Accept()
			if err != nil {
				log.Printf("accept (ldaps): %+v", err)
				continue
			}
			sess := &ldap.Session{Conn: c, Dir: dir, Store: store, TlsConfig: tlsConf, TlsActive: true}
			go sess.Serve()
		}
	} else {
		select {}
	}
}
