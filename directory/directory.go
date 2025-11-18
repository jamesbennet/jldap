package directory

import (
	"log"
	"strings"
	"sync/atomic"
)

/*
The Entry struct models a single object/node/record, with associated attributes, in a hierarchical directory tree.
*/
type Entry struct {
	// DN = Distinguished Name - The unique identifier for an LDAP entry.
	DN string
	// A map of attribute name → list of values. LDAP attributes can have multiple values, so each is a slice of strings.
	Attrs map[string][]string
	// A list of DNs of child entries in the directory tree. Represents directory hierarchy: this entry is a parent, and these are its children.
	Children []string
	// The DN of the parent entry. Useful for navigating upward in the directory tree.
	Parent string
}

/*
The Directory struct models the entire in-memory directory database, containing many entries and various indexes for fast lookup.
It acts as the container or database engine for all Entry nodes.
*/
type Directory struct {
	// A lookup map: DN → Entry, which lets you quickly retrieve any entry by its distinguished name. This is the main index mapping DNs to entries.
	ByDN map[string]*Entry
	// A lookup map: uid → DN, which makes it fast to find a user by UID (common LDAP pattern). A secondary index for fast user lookup by UID
	ByUID map[string]string
	// A lookup map: common name → list of DNs. CNs aren't unique, so the value is a slice of DNs.
	byCN map[string][]string
	// The root DN of the directory.
	BaseDN string
}

/*
The NewDirectory function takes one parameter: a baseDN of type string. It returns a pointer to a Directory (*Directory).
It's effectively a constructor that returns an initialized instance.
NewDirectory(baseDN) builds an in-memory LDAP-like directory structure with:
(1) A root domain entry at baseDN.
(2) A users organizational unit under that root.
(3) A groups organizational unit under that root.
(4) Internal maps ready so you can look things up by DN, UID, CN, etc.
*/
func NewDirectory(baseDN string) *Directory {
	// Creates a new Directory value using a struct literal.
	// &Directory{ ... } takes the address of that struct value, so d is a *Directory.
	d := &Directory{
		// Initializes the ByDN field with an empty map.
		// Key type: string (The DN - distinguished name).
		// Value type: *Entry (pointer to an Entry).
		ByDN: map[string]*Entry{},
		// Initializes ByUID as an empty map from user ID (uid) to some string (the DN).
		ByUID: map[string]string{},
		// Initializes byCN, a map from a string (the common name, CN) to a slice of strings, a list of DNs or UIDs that share that CN.
		byCN: map[string][]string{},
		// Sets the BaseDN field of Directory to the argument baseDN passed into the function.
		BaseDN: baseDN,
	}
	// At this point, we have a Directory with its internal maps ready to use and its base DN recorded, but no entries inside yet.
	// Below, we are creating the root entry corresponding to baseDN.
	d.Add(&Entry{
		// Sets the DN (distinguished name) of the entry to baseDN. This is the top-level domain entry in the directory tree.
		DN:    baseDN,
		Attrs: attrs("objectClass", "top", "objectClass", "domain", "dc", firstDC(baseDN)),
	})
	// At this point, the root domain entry has been added to the directory.
	// This next entry will represent the ou=users organizational unit.
	// We build the DN string by concatenating "ou=users," with baseDN, and set the Parent field of the entry to baseDN.
	d.Add(&Entry{
		DN:     "ou=users," + baseDN,
		Attrs:  attrs("objectClass", "top", "objectClass", "organizationalUnit", "ou", "users"),
		Parent: baseDN,
	})
	// Same for groups
	d.Add(&Entry{
		DN:     "ou=groups," + baseDN,
		Attrs:  attrs("objectClass", "top", "objectClass", "organizationalUnit", "ou", "groups"),
		Parent: baseDN,
	})
	// Returns the fully constructed *Directory value, with its maps (ByDN, ByUID, byCN) initialized, the BaseDN field set, and at least three entries added:
	// (1) The base domain entry (DN = baseDN)
	// (2) ou=users,baseDN
	// (3) ou=groups,baseDN
	return d
}

/*
The attrs function takes an even-length list of strings and turns them into a map[string][]string, where:
(1) each pair of strings represents a key and value.
(2) keys are lower-cased.
(3) multiple values for the same key are collected into a slice.
*/
func attrs(kv ...string) map[string][]string {
	if len(kv)%2 != 0 {
		// If the number of strings is odd, log a warning.
		// NOTE: It doesn’t crash; it will still run but will ignore the last argument, as a workaround.
		log.Printf("attrs(): expected key/value pairs (even count), got %d: %#v. ignoring last.", len(kv), kv)
		kv = kv[:len(kv)-1]
	}
	// Creates an empty map where each key maps to a slice of strings.
	m := map[string][]string{}
	for i := 0; i < len(kv); i += 2 {
		// Steps through the input two items at a time (i += 2).
		// kv[i] → key, kv[i+1] → value
		// We make the key case-insensitive.
		k := strings.ToLower(kv[i])
		v := kv[i+1]
		// Adds the value to the slice at that key (creating the slice if needed).
		m[k] = append(m[k], v)
	}
	// Returns the map containing all the aggregated attributes.
	return m
}

/*
The Add function adds an LDAP-style entry (*Entry) into an in-memory directory index (*Directory).
The directory maintains a parent→children tree.
It stores the entry under multiple lookup tables: by DN, by UID, by CN, and it updates parent/child relationships.
*/
func (d *Directory) Add(e *Entry) {
	// We normalize the DN (DNs are case-insensitive), and store the entry by DN.
	// This allows for a fast lookup of entries using directory.ByDN
	lowerDN := strings.ToLower(e.DN)
	d.ByDN[lowerDN] = e
	// If it has a parent, normalize parent DN and look it up, so we can update the parent’s children list.
	if e.Parent != "" {
		parent := d.ByDN[strings.ToLower(e.Parent)]
		if parent != nil {
			// If the parent exists, append this entry's (non-lowercased) DN to parent.Children.
			parent.Children = append(parent.Children, e.DN)
		}
	}
	// Index by UID (first UID only), to allow for a fast lookup: directory.ByUID["jdoe"] → dn.
	// We look for the "uid" attribute (LDAP-style usernames). If the entry has at least one UID, convert the first UID to lowercase, and map that UID to the entry's DN.
	if uids, ok := e.Attrs["uid"]; ok && len(uids) > 0 {
		d.ByUID[strings.ToLower(uids[0])] = lowerDN
	}
	// Index by CN (possibly multiple CNs)
	if cns, ok := e.Attrs["cn"]; ok {
		// A "cn" (common name) can have multiple values. For each CN, lowercase it, and add the DN to d.byCN[cn], which is a slice (because many entries can share a CN).
		for _, cn := range cns {
			l := strings.ToLower(cn)
			d.byCN[l] = append(d.byCN[l], lowerDN)
		}
	}
}

// The Get function converts the DN to lowercase and returns the Entry stored under that key in the directory. If nothing is there, return nil.
func (d *Directory) Get(dn string) *Entry {
	return d.ByDN[strings.ToLower(dn)]
}

/*
The Subtree function returns all entries in the directory that are in the subtree rooted at startDN.
It performs a depth-first search (DFS) starting from startDN and collects every Entry it encounters.
In other words, given a starting node DN, return that node + all of its descendants, i.e. a slice of pointers to Entry.
*/
func (d *Directory) Subtree(startDN string) []*Entry {
	// Look up the starting entry - We need to ensure the starting DN exists.
	// Directory maps distinguished names (DNs) → Entry objects.
	// Each Entry has a Children []string field listing the DN of each child.
	// Directory.Get(dn) retrieves an *Entry for a given DN.
	// If it doesn't exist, return nil (subtree is empty).
	start := d.Get(startDN)
	if start == nil {
		return nil
	}
	// acc will accumulate all entries found during the traversal.
	var acc []*Entry
	// Defines a recursive function named dfs.
	var dfs func(dn string)

	// Previously there was no cycle detection. If a bad Entry had Parent/Children forming a cycle (e.g. via external mutation), Subtree would recurse infinitely and stack overflow. Now, we track visited DNs.
	visited := make(map[string]bool)
	dfs = func(dn string) {
		ldn := strings.ToLower(dn)
		if visited[ldn] {
			return
		}
		visited[ldn] = true
		// Retrieve the entry. If not found, stop recursion for that branch.
		e := d.Get(dn)
		if e == nil {
			return
		}
		// Add this entry to the results.
		acc = append(acc, e)
		// Recursively visit each child DN node and it's children.
		for _, c := range e.Children {
			dfs(c)
		}
	}
	// Start the DFS at the root DN, then return all collected entries.
	dfs(startDN)
	return acc
}

/*
The ChildrenOf function returns the child entries of a directory node, as a slice of pointers to Entry.
It takes a string startDN, representing the node’s distinguished name (DN).
If the node doesn't exist, it returns nil.
*/
func (d *Directory) ChildrenOf(startDN string) []*Entry {
	// look up the entry with that DN. If no such entry exists, return nil.
	start := d.Get(startDN)
	if start == nil {
		return nil
	}
	var out []*Entry
	// Go over a list of DNs of child entries.
	// For each c (child DN), look up the child entry using d.Get(c)
	// If found, append the entry to out. If a child DN has no corresponding entry, it's silently skipped.
	for _, c := range start.Children {
		if e := d.Get(c); e != nil {
			out = append(out, e)
		}
	}
	// Returns the slice of resolved child entries. If the original DN existed but had no valid children, you get an empty slice (not nil).
	return out
}

/*
The MemberOf function returns all directory entries (usually groups) that the entry with distinguished name dn is a member of.
It supports two forms of group membership:
(1) member → DN references (e.g., member: uid=bob,ou=People,dc=example,dc=com)
(2) memberUid → username references (e.g., memberUid: bob)
This mirrors what OpenLDAP and other LDAP servers do for group entries.
It finds all groups that list the entry either by:
* DN (member)
* lowercased UID (memberUid)
With case-insensitive matching everywhere, and no duplicates.
It returns a slice of group DNs
NOTE: MemberOf is O(#entries × #members)` and as every MemberOf call does a full scan of ByDN. For large directories this will be slow. We probably should maintain reverse indexes when adding entries, instead.
*/
func (d *Directory) MemberOf(dn string) []string {
	// Look up the entry for the given DN.  If it doesn’t exist, return nil.
	e := d.Get(dn)
	if e == nil {
		return nil
	}
	// Extract the entry’s UID, lowercased. Some groups identify members by UID instead of DN. We normalize the UID to lowercase for case-insensitive matching.
	uid := ""
	if uids, ok := e.Attrs["uid"]; ok && len(uids) > 0 {
		uid = strings.ToLower(uids[0])
	}
	// prevent duplicates - An entry may match both member and memberUid, so dedupe by DN.
	seen := make(map[string]bool)
	var out []string
	// d.ByDN is a map keyed by a lower-cased DN; ent.DN contains the original DN.
	for lowerDN, ent := range d.ByDN {
		// Each entry might be a group that references our target entry.
		// We check whether the group’s "member" attribute contains our DN (case-insensitive).
		if ms, ok := ent.Attrs["member"]; ok {
			for _, mdn := range ms {
				if strings.EqualFold(mdn, dn) {
					if !seen[lowerDN] {
						// Add the group’s DN to the result.
						seen[lowerDN] = true
						out = append(out, ent.DN)
					}
					// Break to avoid scanning more "member" values in this entry.
					break
				}
			}
		}
		if uid != "" {
			// If the entry had a UID, Check whether the group contains our UID in "memberUid". If yes, add it to the result (again with duplicate protection):
			if mus, ok := ent.Attrs["memberuid"]; ok {
				for _, u := range mus {
					if strings.EqualFold(u, uid) {
						if !seen[lowerDN] {
							seen[lowerDN] = true
							out = append(out, ent.DN)
						}
						break
					}
				}
			}
		}
	}
	return out
}

// DirStore is just a tiny wrapper providing an atomic pointer to the directory object, so we can update LDAP directory data live
// atomic.Value allows you to store any value (an interface{}) and load it atomically without locks, meaning operations are safe for concurrent access,no problems with partial writes or corrupted data.
type DirStore struct{ val atomic.Value }

/*
The Get function retrieves the current value stored inside the DirStore's atomic.Value and returns it as a *Directory.
It gives you the current directory snapshot in a lock-free, thread-safe way.
*/
func (s *DirStore) Get() *Directory {
	// atomic.Value.Load() returns the current stored value - The return type is interface{}, so it could be anything (or nil).
	// If nothing has ever been stored, Load() returns nil. In that case, Get() itself returns nil.
	v := s.val.Load()
	if v == nil {
		return nil
	}
	// Since the code expects a *Directory was previously stored, it asserts v is of type *Directory.
	// If something else was stored (wrong type), it panics—this is normal for atomic.Value, since consistency of types is required.
	return v.(*Directory)
}

/*
The Set function atomically replaces the value stored inside the DirStore with the new *Directory pointer d.
It’s just a thin wrapper around atomic.Value.Store()
All readers calling Get() will instantly start seeing d as the new value — no locks needed, no partial writes.
Any number of goroutines can call Get() while one goroutine calls Set(). No locking is required. Readers will always see a valid pointer.
*/
func (s *DirStore) Set(d *Directory) { s.val.Store(d) }

/*
The firstDC function extracts the first domain component (DC) from an LDAP Base DN.
If no dc= component is found, it falls back to "homelab".
*/
func firstDC(baseDN string) string {
	// Splits the Base DN into components by commas:
	parts := strings.Split(baseDN, ",")
	// Loop through each DN component, trimming whitespace.
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Check if the part starts with "dc=", in a case-insensitive way.
		if strings.HasPrefix(strings.ToLower(p), "dc=") {
			// Extract the value after "dc="
			// The function returns immediately after finding the first dc=.
			return p[len("dc="):]
		}
	}
	// Used when no domain component is found in baseDN - a safe fallback.
	return "homelab"
}
