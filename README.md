# JLDAP

**⚠️This app is designed for use in my Homelab (trusted internal network). _NOT_ for production / Internet exposure!⚠️**

## Goal

### Requirements

I wanted to build a very simple hobby LDAP _v3_ server (which I eventually called _JLDAP_), in Go, using **no** external libraries (_only stuff from the go stdlib_), and having **no** external dependencies like a DB at all. The aim was for just a single process to run, with a single config file, a single binary to deploy.

I wanted it to be able to store users/groups so that I could use it when authenticating from common webapps running in my HomeLab, such as:

* _gitea_
* _jenkins_
* _dokuwiki_
* _keycloak_
* _nexus_
* _portainer_
* _proxmox_

So, it basically needed to be able to:
* Bind (_including anonymous_).
* List/read things.
* Search/filter/compare things.
* Get groups users are members of.
* etc...

And it needed to support browsing tools like _ldapsearch_, _phpLDAPadmin_ (_no need to support editing, just browsing/viewing_).

### Anti-Requirements

I did _not_ need support for daemons like _pam_/_nss_ etc..., just those common webapps (_If I wanted that, I would have run something heavyweight like FreeIPA or 389DS_).

Basically it needed to meet **_just_** enough standards to get the job done. It does **not** need to be as complicated as alternatives like LLDAP or GLAuth.

While I did want some security such as SSL/TLS (_I have implemented support for LDAPS/STARTTLS, and SASL PLAIN_), I was not fussed about implementing ACLs or password hashing or rate-limiting, or anything like that. I just aimed for something as simple as possible. Data is loaded from a JSON file and held in-memory with _**plaintext**_ passwords (_⚠️ - again, this is just a hobby project_), no support for importing LDIF files or anything.

## Comparison

Compared to _lldap_ and _glauth_, in the Homelab context:

(1) **LLDAP**

* A heavy, fully-featured, modern auth server.
* Closer to running a small Keycloak.
*  ✔ Full identity provider
*  ✔ Web UI, PostgreSQL DB
*  ✔ MFA, WebAuthn
*  ✔ Password hashing
*  ✔ Complex schema, virtual attributes
*  ✔ Real ACLs
*  ✔ Reset-password flows
*  ✔ Tokens, sessions, groups, RBAC
* ✘ Heavy: requires Postgres, multi-container deployments
* ✘ More moving parts, upgrades, storage
* ✘ Overkill if all you need is “bind + search” LDAP for a few apps

(2) **GLAuth**

* A lightweight Go-based auth proxy with config files.
* ✔ Go-based, lightweight
* ✔ TOML config
* ✔ Supports LDAP-ish binds and groups
* ✔ Good for simple SSO-ish setups
* ✔ No external DB by default
* ✘ Not a full LDAP server (does not fully implement LDAP v3) - Incompatible with many apps expecting real LDAP behaviour.
* ✘ Search filters & subtree searches are very limited
* ✘ No StartTLS
* ✘ No LDAPS unless reverse-proxied
* ✘ Many apps (Jenkins, Gitea, Keycloak) require real LDAP semantics that GLAuth does not implement
* ✘ Configuration is more oriented around “proxy-style” auth, not full directory browsing

(3) **JLDAP**

**This!**
* A tiny, standards-compliant LDAP v3 responder.
* A drop-in lightweight LDAP identity source for apps that expect an LDAP server, with zero infrastructure.
*  ✔ Minimal, transparent, as small as possible
*  ✔ Real LDAP v3 protocol (bind/search/compare)
*  ✔ Single process, single JSON file, single binary
*  ✔ No database, no external libraries
*  ✔ An in-memory directory that mirrors the JSON file.
*  ✔ Just enough RFC compliance for Gitea/Jenkins/etc
*  ✔ Trusted homelab use only
*  ✘ No password hashing
*  ✘ No ACLs
*  ✘ No multi-domain, no token issuing
*  ✘ No multi-factor, no OIDC, no web-based auth
*  ✘ No write operations via LDAP (read-only LDAP)
*  ✘ Not suitable for PAM/NSS

| Feature                                          | JLDAP                               | LLDAP                | GLAuth                |
|--------------------------------------------------|-------------------------------------|----------------------|-----------------------|
| Full LDAP v3 BER encoder/decoder                 | **Yes (handwritten)**               | Yes                  | **No (partial)**      |
| Bind (simple)                                    | Yes                                 | Yes                  | Yes                   |
| SASL PLAIN                                       | **Yes**                             | Yes                  | No                    |
| Anonymous bind                                   | Yes                                 | Yes                  | Yes                   |
| Search filters (AND/OR/NOT, substring, presence) | **Yes**                             | Yes                  | **No (very limited)** |
| Subtree search                                   | **Yes**                             | Yes                  | Partial               |
| Compare op                                       | **Yes**                             | Yes                  | No                    |
| Root DSE                                         | **Yes**                             | Yes                  | No                    |
| cn=subschema                                     | **Yes**                             | Yes                  | No                    |
| StartTLS                                         | **Yes**                             | Yes                  | **No**                |
| LDAPS                                            | **Yes**                             | Yes                  | **No (needs proxy)**  |
| Modify/Add/Delete                                | **Ish** (_read-only LDAP but has API/UI_) | Yes                  | No                    |
| memberOf virtual attribute                       | **Yes**                             | Yes                  | No                    |
| External DB                                      | **No**                              | **Yes (PostgreSQL)** | No                    |
| Config format                                    | **JSON**                            | YAML                 | TOML                  |
| Hot reload                                       | **Yes (SIGHUP + 10min poll)**       | No                   | Limited               |
| Persist changes                                  | **Yes (writes JSON)**               | Yes                  | Yes                   |
| Password hashing                                 | **No**                              | Yes                  | Yes                   |
| Multi-domain                                     | No                                  | **Yes**              | No                    |

For homelab apps like Gitea, Jenkins, Proxmox, DokuWiki, Keycloak, etc... LLDAP is (_for me_), the way to go.

**tl;dr**: _JLDAP = The smallest/simplest LDAP server that is compatible with actual apps. Perfect for homelab services that only need bind/search/group membership over LDAPS/StartTLS_

### The Database

**Note**: From an LDAP perspective things are for now **read-only** (_no way to add/modify/delete things via LDAP_). Though that JSON file **is** hot-reloadable on _SIGHUP_, and/or every 10 minutes on a timer, if changes are detected, or via the `/api/reload` admin API endpoint.

There **is** however, an (_optional_) authenticated (HTTP Basic Auth, using LDAP creds for a user in a designated admins group) REST API served over HTTPS (_only_), using same TLS cert as LDAPS:

* GET `/api/users` → _List all users_
* GET `/api/users/{uid}` → _Get one user_
* POST `/api/users` → _Create or partial-update user (upsert)_
* DELETE `/api/users/{uid}` → _Delete user_
* GET `/api/groups` → _List all groups_
* GET `/api/groups/{cn}` → _Get one group_
* POST `/api/groups` → _Create or partial-update group (upsert)_
* DELETE `/api/groups/{cn`} → _Delete group_
* GET `/api/users/{uid}/groups` → _User + memberOf._
* GET `/api/groups/{cn}/members` → _Group + expanded member users._
* GET `/api/debug/dump` → _JSON config._
* POST `/api/reload` → _Force JSON reload into Directory + ConfigStore._

This API **does** allow you to modify the data - i.e. you can POST this sort of thing to `/api/users` or `/api/groups`:

```json
{
    "cn":"Jane Smith","sn":"Smith","givenName":"Jane",
    "uid":"jsmith","mail":"jane.smith@homelab.lan",
    "userPassword":"secret",
    "uidNumber":"2002","gidNumber":"2001",
    "homeDirectory":"/home/jsmith","loginShell":"/bin/bash"
}
```

```json
{
    "cn":"devs",
    "gidNumber":"2002",
    "memberUid":["jbennet"],
    "member":["uid=jbennet,ou=users,dc=homelab,dc=lan"]
}
```

Changes will then be written out to the JSON file on disk and applied (_It's smart enough to group references when deleting a user_).

There is also a small **UI** at:

* `https://<host>:<port>/ui`
* `https://<host>:<port>/ui/users/new`
* `https://<host>:<port>/ui/users/edit?uid=<uid>`
* `https://<host>:<port>/ui/groups/new`
* `https://<host>:<port>/ui/groups/edit?cn=<cn>`

You need to be an admin to use it. Passwords are redacted in responses. There is CSRF / HSTS / X-Frame-Options / CSP headers, but it's all very basic, just a _proof-of-concept_. See the **many** Hardening related TODOs in `TODO.txt`.

![UI](docs/img/ui.png?raw=true "UI")
![User](docs/img/user.png?raw=true "User")
![Groups](docs/img/groups.png?raw=true "Groups")

It has some info about the server state, as well as a search and buttons to promote users to admins and stuff, which is nice.

## Testing

In terms of test data I just insert the following defaults - If you don't drop in a custom `jldap.json`, it should fall back to putting this sample data in:

* Base DN: `dc=homelab,dc=lan`
* User: 
  * Full name: `James Bennet`
  * First Name: `James`
  * Surname: `Bennet`
  * Username: `jbennet`
  * Email: `james.bennet@homelab.lan`
  * Password: `password1234` (Obviously not a real email or password!)
* Groups: `homelab_admins`
  * Members: `jbennet`

So, JSON config like this:

```json
{
  "baseDN": "dc=homelab,dc=lan",
  "adminUsersCN": "homelab_admins",
  "users": [
    {
      "cn": "James Bennet",
      "sn": "Bennet",
      "givenName": "James",
      "uid": "jbennet",
      "mail": "james.bennet@homelab.lan",
      "userPassword": "password1234",
      "uidNumber": "1001",
      "gidNumber": "2001",
      "homeDirectory": "/home/jbennet",
      "loginShell": "/bin/bash",
      "objectClass": ["top","person","organizationalPerson","inetOrgPerson","posixAccount"]
    }
  ],
  "groups": [
    {
      "cn": "homelab_admins",
      "gidNumber": "2001",
      "memberUid": ["jbennet"],
      "member": ["uid=jbennet,ou=users,dc=homelab,dc=lan"],
      "objectClass": ["top","posixGroup","groupOfNames"]
    }
  ]
}
```

To test in _JXplorer_:

* Host: `localhost`
* Port: `1636`
* Protocol: `LDAP v3`
* Base DN: `dc=homelab,dc=lan`
* Level: `SSL + User + Password`
* User DN: `uid=jbennet,ou=users,dc=homelab,dc=lan`
* Password: `password1234`

![JXplorer](docs/img/jxplorer.png?raw=true "JXplorer")
![JXplorer 2](docs/img/jxplorer2.png?raw=true "JXplorer 2")

## Running

To run:

```bash
go build
# Create a private key (RSA 4096-bit) and self-signed certificate valid 10 years
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 3650 -nodes  -subj "/C=US/ST=Test/L=Local/O=Homelab/CN=localhost"
./jldap.exe -data jldap.json -listen 0.0.0.0:1389 -starttls -ldaps 0.0.0.0:1636 -http 0.0.0.0:8443 -tls-cert server.crt -tls-key server.key
```

In terms of the CLI args:

```bash
$ ./jldap -help
Usage of C:\Users\jdben\GolandProjects\jldap\jldap.exe:
  -data string
        path to JSON file with baseDN, users, groups (e.g, jldap.json (default "jldap.json")
  -http string
        HTTPS API address for POST/DELETE users/groups (default "0.0.0.0:8443")
  -ldaps string
        LDAPS address to listen on (e.g., 0.0.0.0:1636) (default "0.0.0.0:1636")
  -listen string
        LDAP address to listen on (e.g., 0.0.0.0:1389) (default "0.0.0.0:1389")
  -starttls
        Enable StartTLS on the plain LDAP listener (requires -tls-cert/-tls-key) (default true)
  -tls-cert string
        TLS certificate PEM (required for StartTLS/LDAPS) (default "server.crt")
  -tls-key string
        TLS private key PEM (required for StartTLS/LDAPS) (default "server.key")
```

If it's started nicely, you'll get something like this:

```bash
2025/11/17 00:47:24.273687 jldap/main.go:244: LDAP listening on 0.0.0.0:1389; base DN: dc=homelab,dc=lan (StartTLS: true)
2025/11/17 00:47:24.273687 jldap/main.go:260: LDAPS listening on 0.0.0.0:1636
2025/11/17 00:47:24.273687 jldap/web/web.go:312: HTTPS API listening on https://0.0.0.0:8443
```

## Example Configs

### GITEA

Go to: `Site Administration → Identity & Access → Authentication Sources [Direct bind (simplest)]`:

* Authentication Type: `LDAP (simple auth)`
* Name: `Homelab LDAP`
* Security Protocol: `LDAPS`
* Host: `localhost`
* Port: `1636`
* Skip TLS Verify: `True`
* Bind DN: `uid=jbennet,ou=users,dc=homelab,dc=lan`
* Bind Password: `password1234`
* User Search Base: `dc=homelab,dc=lan`
* User DN: `uid=%s,ou=users,dc=homelab,dc=lan`
* User Filter: `(&(objectClass=inetOrgPerson)(uid=%s))`
* Admin filter: `(memberOf=cn=homelab_admins,ou=groups,dc=homelab,dc=lan)`
* Restricted Filter: `(memberOf=cn=homelab_admins,ou=groups,dc=homelab,dc=lan)`
* Username attribute: `uid`
* First name attribute: `givenName`
* Surname attribute: `sn`
* Email attribute: `mail`
* Display name attribute: `cn`
* Group Search Base DN: `ou=groups,dc=homelab,dc=lan`
* Group Attribute Containing List Of Users: `member`
* User Attribute Listed In Group: `dn`
* Filter to Verify group membership in LDAP: `(&(objectClass=groupOfNames)(cn=homelab_admins))`
* Map LDAP groups to Organization teams:
```json
{
"cn=homelab_admins,ou=groups,dc=homelab,dc=lan": {
"Homelab": ["Admins"]
}
}
```

### JENKINS

Go to: `Jenkins → Manage Jenkins → Security`:

* Security Realm: `LDAP`
* Server: `ldap://localhost:1389`
* Root DN: `dc=homelab,dc=lan`
* User search base: `ou=users`
* User search filter: `(&(objectClass=inetOrgPerson)(uid={0}))`
* Group search base: `ou=groups`
* Group search filter: `(cn={0})`
* Group membership strategy: `Parse user attribute for list of LDAP groups: (“memberOf”)`
* Manager DN / Password: `uid=jbennet,ou=users,dc=homelab,dc=lan / password1234`
* Display Name LDAP attribute: `cn`
* Email Address LDAP attribute: `mail`
* User DN pattern (Advanced): `uid={0},ou=users,dc=homelab,dc=lan`

If you prefer not to rely on `memberOf`, switch strategy to _From group search_ and set _Group membership filter_: `member={0}`

Click “_Test LDAP settings_” in Jenkins with:

```
Username: jbennet
Password: password1234
```

![Jenkins](docs/img/jenkinstest.png?raw=true "Jenkins")

Then something like:

* Set authorization to Matrix-based security.
* Add user jbennet and group homelab_admins
* Give them `Overall › Administer`, (_and whatever else_)
* After login, Jenkins should show you as a member of `homelab_admins`, and you should have admin rights.

### Other Services

Use these across Gitea/Jenkins/DokuWiki/Keycloak/Nexus/Portainer/Proxmox:

* Server URL: `ldap://localhost:1389` (or `ldaps://localhost:1636`)
* StartTLS: Enable if using `ldap://` (optional with LDAPS).
* Bind DN (_optional_): You can use anonymous or a service account if you add one later.
* Base DN: `dc=homelab,dc=lan`
* User search DN: `ou=users,dc=homelab,dc=lan`
* User filter: `(&(objectClass=inetOrgPerson)(uid=%s))`  - You can also do email.
* User unique ID: `uid` (_or mail as needed_).
* Group search base DN: `ou=groups,dc=homelab,dc=lan`
* Group objectClass: `posixGroup` or `groupOfNames`.
* Group member attribute: Supports both `member` (_DNs_) and `memberUid` (_UIDs_)
* Optional group mapping: Filter by `cn=homelab_admins`.
* Groups for user membership: `memberOf`