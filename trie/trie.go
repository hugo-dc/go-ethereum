// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime/debug"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"github.com/rcrowley/go-metrics"
)

var (
	// This is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	// This is the known hash of an empty state trie entry.
	emptyState common.Hash
)

var (
	cacheMissCounter   = metrics.NewRegisteredCounter("trie/cachemiss", nil)
	cacheUnloadCounter = metrics.NewRegisteredCounter("trie/cacheunload", nil)
)

// CacheMisses retrieves a global counter measuring the number of cache misses
// the trie had since process startup. This isn't useful for anything apart from
// trie debugging purposes.
func CacheMisses() int64 {
	return cacheMissCounter.Count()
}

// CacheUnloads retrieves a global counter measuring the number of cache unloads
// the trie did since process startup. This isn't useful for anything apart from
// trie debugging purposes.
func CacheUnloads() int64 {
	return cacheUnloadCounter.Count()
}

func init() {
	sha3.NewKeccak256().Sum(emptyState[:0])
}

// Database must be implemented by backing stores for the trie.
type Database interface {
	DatabaseReader
	DatabaseWriter
}

// DatabaseReader wraps the Get method of a backing store for the trie.
type DatabaseReader interface {
	Get(bucket, key []byte) (value []byte, err error)
	First(bucket, key, suffix []byte) ([]byte, error)
	Has(bucket, key []byte) (bool, error)
	Walk(bucket, key []byte, keybits uint, walker ethdb.WalkerFunc) error
}

// DatabaseWriter wraps the Put method of a backing store for the trie.
type DatabaseWriter interface {
	// Put stores the mapping key->value in the database.
	// Implementations must not hold onto the value bytes, the trie
	// will reuse the slice across calls to Put.
	Put(bucket, key, value []byte) error
	PutS(bucket, key, suffix, value []byte) error
	DeleteSuffix(suffix []byte) error
}

// Trie is a Merkle Patricia Trie.
// The zero value is an empty trie with no database.
// Use New to create a trie that sits on top of a database.
//
// Trie is not safe for concurrent use.
type Trie struct {
	root         node
	originalRoot common.Hash

	// Prefix to form the database key
	prefix []byte

	nodeList *List
}

func (t *Trie) PrintTrie() {
	if fn, ok := t.root.(*fullNode); ok {
		fmt.Printf("%s\n", fn.String())
	}
}

// newFlag returns the cache flag value for a newly created node.
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{next: nil, prev: nil}
}

// New creates a trie with an existing root node from db.
//
// If root is the zero hash or the sha3 hash of an empty string, the
// trie is initially empty and does not require a database. Otherwise,
// New will panic if db is nil and returns a MissingNodeError if root does
// not exist in the database. Accessing the trie loads nodes from db on demand.
func New(root common.Hash, prefix []byte) *Trie {
	trie := &Trie{originalRoot: root, prefix: prefix}
	if (root != common.Hash{}) && root != emptyRoot {
		rootcopy := make([]byte, len(root[:]))
		copy(rootcopy, root[:])
		trie.root = hashNode(rootcopy)
	}
	return trie
}

func (t *Trie) MakeListed(nodeList *List) {
	t.nodeList = nodeList
	t.relistNodes(t.root)
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
func (t *Trie) NodeIterator(dbr DatabaseReader, start []byte, blockNr uint64) NodeIterator {
	return newNodeIterator(dbr, t, start, blockNr)
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
func (t *Trie) Get(dbr DatabaseReader, key []byte, blockNr uint64) []byte {
	res, err := t.TryGet(dbr, key, blockNr)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

// TryGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryGet(dbr DatabaseReader, key []byte, blockNr uint64) ([]byte, error) {
	if t.nodeList != nil {
		// We want t.root to be evaluated on exit, not now
		defer func() { t.relistNodes(t.root) }()
	}
	k := keybytesToHex(key)
	value, newnode, didResolve, err := t.tryGet1(dbr, t.root, k, 0, blockNr, false)
	if err != nil {
		return value, err
	}
	if didResolve {
		t.root = newnode
	} else {
		value, err = t.tryGet(dbr, t.root, k, 0, blockNr)
	}
	return value, err
}

// Touching the node removes it from the nodeList
func (t *Trie) touch(np nodep) {
	if t.nodeList != nil && np != nil && np.next() != nil && np.prev() != nil {
		t.nodeList.Remove(np)
	}
}

// Re-adds nodes to the nodeList after being touched (and therefore removed from the list)
func (t *Trie) relistNodes(n node) {
	if n == nil {
		return
	}
	if !n.unlisted() {
		// Reached the node that has not been touched
		return
	}
	switch n := (n).(type) {
	case *shortNode:
		// First re-add the child, then self
		t.relistNodes(n.Val)
		t.nodeList.PushToBack(n)
	case *duoNode:
		t.relistNodes(n.child1)
		t.relistNodes(n.child2)
		t.nodeList.PushToBack(n)
	case *fullNode:
		// First re-add children, then self
		for i := 0; i<=16; i++ {
			if n.Children[i] != nil {
				t.relistNodes(n.Children[i])
			}
		}
		t.nodeList.PushToBack(n)
	}
}

func (t *Trie) tryGet(dbr DatabaseReader, origNode node, key []byte, pos int, blockNr uint64) (value []byte, err error) {
	suffix := make([]byte, 8)
	binary.BigEndian.PutUint64(suffix, blockNr^0xffffffffffffffff - 1) // Invert the block number
	enc, err := dbr.First(t.prefix, hexToKeybytes(key), suffix)
	if err != nil || enc == nil || len(enc) == 0 {
		return nil, nil
	}
	val, _, err := rlp.SplitString(enc)
	return val, err
}

func (t *Trie) tryGet1(dbr DatabaseReader, origNode node, key []byte, pos int, blockNr uint64, force bool) (value []byte, newnode node, didResolve bool, err error) {
	if np, ok := origNode.(nodep); ok {
		t.touch(np)
	}
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		nKey := compactToHex(n.Key)
		if len(key)-pos < len(nKey) || !bytes.Equal(nKey, key[pos:pos+len(nKey)]) {
			return nil, n, false, nil
		}
		value, newnode, didResolve, err := t.tryGet1(dbr, n.Val, key, pos+len(nKey), blockNr, force)
		nn := n
		if err == nil && didResolve {
			nn = n.copy()
			nn.flags = t.newFlag()
			nn.Val = newnode
		}
		return value, nn, didResolve, err
	case *duoNode:
		i1, i2 := n.childrenIdx()
		nn := n
		switch key[pos] {
		case i1:
			value, newnode, didResolve, err = t.tryGet1(dbr, n.child1, key, pos+1, blockNr, force)
			if err == nil && didResolve {
				nn = n.copy()
				nn.flags = t.newFlag()
				nn.child1 = newnode
			}
		case i2:
			value, newnode, didResolve, err = t.tryGet1(dbr, n.child2, key, pos+1, blockNr, force)
			if err == nil && didResolve {
				nn = n.copy()
				nn.flags = t.newFlag()
				nn.child2 = newnode
			}
		default:
			return nil, n, false, nil
		}
		return value, nn, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.tryGet1(dbr, n.Children[key[pos]], key, pos+1, blockNr, force)
		nn := n
		if err == nil && didResolve {
			nn = n.copy()
			nn.flags = t.newFlag()
			nn.Children[key[pos]] = newnode
		}
		return value, nn, didResolve, err
	case hashNode:
		if !force {
			return nil, n, false, nil
		}
		rn, err := t.resolveHash(dbr, n, key, pos, blockNr)
		if err != nil {
			return nil, n, false, err
		}
		value, newnode, _, err := t.tryGet1(dbr, rn, key, pos, blockNr, force)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
func (t *Trie) Update(dbr DatabaseReader, key, value []byte, blockNr uint64) {
	if err := t.TryUpdate(dbr, key, value, blockNr); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryUpdate associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryUpdate(dbr DatabaseReader, key, value []byte, blockNr uint64) error {
	if t.nodeList != nil {
		// We want t.root to be evaluated on exit, not now
		defer func() { t.relistNodes(t.root) }()
	}
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(dbr, t.root, k, 0, valueNode(value), blockNr)
		if err != nil {
			fmt.Printf("Error in TryUpdate: %s\n", err)
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(dbr, t.root, k, 0, blockNr)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) insert(dbr DatabaseReader, origNode node, key []byte, pos int, value node, blockNr uint64) (bool, node, error) {
	if np, ok := origNode.(nodep); ok {
		t.touch(np)
	}
	if len(key) == pos {
		if v, ok := origNode.(valueNode); ok {
			dirty := !bytes.Equal(v, value.(valueNode))
			return dirty, value, nil
		}
		return true, value, nil
	}
	switch n := origNode.(type) {
	case *shortNode:
		nKey := compactToHex(n.Key)
		matchlen := prefixLen(key[pos:], nKey)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(nKey) {
			dirty, nn, err := t.insert(dbr, n.Val, key, pos+matchlen, value, blockNr)
			if err != nil || !dirty {
				return false, n, err
			}
			newnode := &shortNode{n.Key, nn, t.newFlag()}
			return true, newnode, nil
		}
		// Otherwise branch out at the index where they differ.
		var err error
		var c1, c2 node
		_, c1, err = t.insert(dbr, nil, nKey, matchlen+1, n.Val, blockNr) // Value already exists
		if err != nil {
			return false, n, err
		}
		_, c2, err = t.insert(dbr, nil, key, pos+matchlen+1, value, blockNr)
		if err != nil {
			return false, n, err
		}
		branch := &duoNode{flags: t.newFlag()}
		/*
		branch := &fullNode{flags: t.newFlag()}
		branch.Children[nKey[matchlen]] = c1
		branch.Children[key[pos+matchlen]] = c2
		*/
		if nKey[matchlen] < key[pos+matchlen] {
			branch.child1 = c1
			branch.child2 = c2
		} else {
			branch.child1 = c2
			branch.child2 = c1
		}
		branch.mask = (1 << (nKey[matchlen])) | (1 << (key[pos+matchlen]))

		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return true, branch, nil
		}
		// Otherwise, replace it with a short node leading up to the branch.
		newnode := &shortNode{hexToCompact(key[pos:pos+matchlen]), branch, t.newFlag()}
		return true, newnode, nil

	case *duoNode:
		i1, i2 := n.childrenIdx()
		switch key[pos] {
		case i1:
			dirty, nn, err := t.insert(dbr, n.child1, key, pos+1, value, blockNr)
			if err != nil || !dirty {
				return false, n, err
			}
			newnode := n.copy()
			newnode.flags = t.newFlag()
			newnode.child1 = nn
			return true, newnode, nil
		case i2:
			dirty, nn, err := t.insert(dbr, n.child2, key, pos+1, value, blockNr)
			if err != nil || !dirty {
				return false, n, err
			}
			newnode := n.copy()
			newnode.flags = t.newFlag()
			newnode.child2 = nn
			return true, newnode, nil
		default:
			dirty, nn, err := t.insert(dbr, nil, key, pos+1, value, blockNr)
			if err != nil || !dirty {
				return false, n, err
			}
			newnode := &fullNode{flags: t.newFlag()}
			newnode.Children[i1] = n.child1
			newnode.Children[i2] = n.child2
			newnode.Children[key[pos]] = nn
			return true, newnode, nil
		}

	case *fullNode:
		dirty, nn, err := t.insert(dbr, n.Children[key[pos]], key, pos+1, value, blockNr)
		if err != nil || !dirty {
			return false, n, err
		}
		newnode := n.copy()
		newnode.flags = t.newFlag()
		newnode.Children[key[pos]] = nn
		return true, newnode, nil

	case nil:
		newnode := &shortNode{hexToCompact(key[pos:]), value, t.newFlag()}
		return true, newnode, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveHash(dbr, n, key, pos, blockNr)
		if err != nil {
			return false, n, err
		}
		dirty, nn, err := t.insert(dbr, rn, key, pos, value, blockNr)
		if !dirty || err != nil {
			return true, rn, err
		}
		return true, nn, nil

	default:
		fmt.Printf("Key: %s, Prefix: %s\n", hex.EncodeToString(key[pos:]), hex.EncodeToString(key[:pos]))
		t.PrintTrie()
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// Delete removes any existing value for key from the trie.
func (t *Trie) Delete(dbr DatabaseReader, key []byte, blockNr uint64) {
	if err := t.TryDelete(dbr, key, blockNr); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// TryDelete removes any existing value for key from the trie.
// If a node was not found in the database, a MissingNodeError is returned.
func (t *Trie) TryDelete(dbr DatabaseReader, key []byte, blockNr uint64) error {
	if t.nodeList != nil {
		// We want t.root to be evaluated on exit, not now
		defer func() { t.relistNodes(t.root) }()
	}
	k := keybytesToHex(key)
	_, n, err := t.delete(dbr, t.root, k, 0, blockNr)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

func (t *Trie) convertToShortNode(dbr DatabaseReader, key []byte, keyStart int, n node, child node, pos int, blockNr uint64) (bool, node, error) {
	if pos != 16 {
		// If the remaining entry is a short node, it replaces
		// n and its key gets the missing nibble tacked to the
		// front. This avoids creating an invalid
		// shortNode{..., shortNode{...}}.  Since the entry
		// might not be loaded yet, resolve it just for this
		// check.
		rkey := make([]byte, len(key))
		copy(rkey, key)
		rkey[keyStart] = byte(pos)
		for i := keyStart + 1; i < len(key); i++ {
			if rkey[i] != 16 {
				rkey[i] = 0
			}
		}
		cnode, err := t.resolve(dbr, child, rkey, keyStart + 1, blockNr)
		if err != nil {
			return false, n, err
		}
		if cnode, ok := cnode.(*shortNode); ok {
			k := append([]byte{byte(pos)}, compactToHex(cnode.Key)...)
			newshort := &shortNode{hexToCompact(k), cnode.Val, t.newFlag()}
			return true, newshort, nil
		}
	}
	// Otherwise, n is replaced by a one-nibble short node
	// containing the child.
	newshort := &shortNode{hexToCompact([]byte{byte(pos)}), child, t.newFlag()}
	return true, newshort, nil	
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
func (t *Trie) delete(dbr DatabaseReader, origNode node, key []byte, keyStart int, blockNr uint64) (bool, node, error) {
	if np, ok := origNode.(nodep); ok {
		t.touch(np)
	}
	switch n := origNode.(type) {
	case *shortNode:
		nKey := compactToHex(n.Key)
		matchlen := prefixLen(key[keyStart:], nKey)
		if matchlen < len(nKey) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) - keyStart {
			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.delete(dbr, n.Val, key, keyStart+len(nKey), blockNr)
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			childKey := compactToHex(child.Key)
			newnode := &shortNode{hexToCompact(concat(nKey, childKey...)), child.Val, t.newFlag()}
			return true, newnode, nil
		default:
			newnode := &shortNode{n.Key, child, t.newFlag()}
			return true, newnode, nil
		}

	case *duoNode:
		i1, i2 := n.childrenIdx()
		switch key[keyStart] {
		case i1:
			dirty, nn, err := t.delete(dbr, n.child1, key, keyStart+1, blockNr)
			if !dirty || err != nil {
				return false, n, err
			}
			if nn == nil {
				return t.convertToShortNode(dbr, key, keyStart, n, n.child2, int(i2), blockNr)
			}
			newnode := n.copy()
			newnode.flags = t.newFlag()
			newnode.child1 = nn
			return true, newnode, nil
		case i2:
			dirty, nn, err := t.delete(dbr, n.child2, key, keyStart+1, blockNr)
			if !dirty || err != nil {
				return false, n, err
			}
			if nn == nil {
				return t.convertToShortNode(dbr, key, keyStart, n, n.child1, int(i1), blockNr)
			}
			newnode := n.copy()
			newnode.flags = t.newFlag()
			newnode.child2 = nn
			return true, newnode, nil
		default:
			return false, n, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(dbr, n.Children[key[keyStart]], key, keyStart+1, blockNr)
		if !dirty || err != nil {
			return false, n, err
		}

		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range n.Children {
			if i == int(key[keyStart]) && nn == nil {
				// Skip the child we are going to delete
				continue
			}
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			return t.convertToShortNode(dbr, key, keyStart, n, n.Children[pos], pos, blockNr)
		}
		// n still contains at least two values and cannot be reduced.
		newnode := n.copy()
		newnode.flags = t.newFlag()
		newnode.Children[key[keyStart]] = nn
		return true, newnode, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveHash(dbr, n, key, keyStart, blockNr)
		if err != nil {
			return false, n, err
		}
		dirty, nn, err := t.delete(dbr, rn, key, keyStart, blockNr)
		if !dirty || err != nil {
			return true, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key[:keyStart]))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(dbr DatabaseReader, n node, key []byte, pos int, blockNr uint64) (node, error) {
	if n, ok := n.(hashNode); ok {
		rn, err := t.resolveHash(dbr, n, key, pos, blockNr)
		return rn, err
	}
	if np, ok := n.(nodep); ok {
		t.touch(np)
	}
	return n, nil
}

func (t *Trie) resolveHash(dbr DatabaseReader, n hashNode, key []byte, pos int, blockNr uint64) (node, error) {
	//fmt.Printf("resolveHash %x %d %d\n", key, pos, blockNr)
	suffix := make([]byte, 8)
	binary.BigEndian.PutUint64(suffix, blockNr^0xffffffffffffffff - 1) // Invert the block number
	endSuffix := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	l := 32
	keyBuffer := make([]byte, l + 8)
	ks := make([]byte, 8)
	copy(ks, endSuffix)
	start := make([]byte, l)
	decodeNibbles(key, start)
	var root node
	newsection := true
	count := 0
	err := dbr.Walk(t.prefix, start, uint(pos*4), func(k, v []byte) []byte {
		if len(k) == 36 {
			copy(ks[4:], k[32:])
		} else if len(k) == 40 {
			copy(ks, k[32:])
		} else {
			panic("Wrong key length")
		}
		//fmt.Printf("k: %x, suffix: %x\n", k, suffix)
		if newsection || (!newsection && !bytes.Equal(k[:l], keyBuffer[:l])) {
			if bytes.Compare(ks, suffix) != -1 {
				var val []byte
				var err error
				if len(v) > 0 {
					val, _, err = rlp.SplitString(v)
					if err != nil {
						panic(fmt.Sprintf("%s", err))
					}
					val_copy := make([]byte, len(val))
					copy(val_copy, val)
					_, root, err = t.insert(dbr, root, keybytesToHex(k[:l]), pos, valueNode(val_copy), blockNr)
					if err != nil {
						panic(fmt.Sprintf("%s", err))
					}
					count++
					if count % 10000 == 0 {
						fmt.Printf("Inserted %d entries\n", count)
					}
				}
				copy(keyBuffer, k[:l])
				copy(keyBuffer[l:], endSuffix)
				newsection = true
				//fmt.Printf("keybuffer (1): %x\n", keyBuffer)
				return keyBuffer
			} else {
				copy(keyBuffer, k[:l])
				copy(keyBuffer[l:], suffix)
				newsection = false
				//fmt.Printf("keybuffer: (2) %x\n", keyBuffer)
				return keyBuffer
			}
		}
		var val []byte
		var err error
		if len(v) > 0 {
			val, _, err = rlp.SplitString(v)
			if err != nil {
				panic(fmt.Sprintf("%s", err))
			}
			val_copy := make([]byte, len(val))
			copy(val_copy, val)
			_, root, err = t.insert(dbr, root, keybytesToHex(k[:l]), pos, valueNode(val), blockNr)
			if err != nil {
				panic(fmt.Sprintf("%s", err))
			}
			count++
			if count % 10000 == 0 {
				fmt.Printf("Inserted %d entries\n", count)
			}
		}
		copy(keyBuffer, k[:l])
		copy(keyBuffer[l:], endSuffix)
		newsection = true
		//fmt.Printf("keybuffer (3): %x\n", keyBuffer)
		return keyBuffer
	})
	if err == nil {
		h := newHasher()
		defer returnHasherToPool(h)
		var gotHash hashNode
		if root != nil {
			hash, _ := h.hash(root, false, key[:pos])
			gotHash = hash.(hashNode)
		}
		if !bytes.Equal(n, gotHash) {
			fmt.Printf("Resolving wrong hash for prefix %x, trie prefix %x block %d\n", key[:pos], t.prefix, blockNr)
			fmt.Printf("Expected hash %s\n", n)
			fmt.Printf("Got hash %s\n", gotHash)
			fmt.Printf("Stack: %s\n", debug.Stack())
			return nil, &MissingNodeError{NodeHash: common.BytesToHash(n), Path: key[:pos]}
		}
	} else {
		fmt.Printf("Error resolving hash: %s\n", err)
	}
	//fmt.Printf("resolveHash]\n")
	return root, err
}

// Root returns the root hash of the trie.
// Deprecated: use Hash instead.
func (t *Trie) Root() []byte { return t.Hash().Bytes() }

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *Trie) Hash() common.Hash {
	hash, _ := t.hashRoot()
	return common.BytesToHash(hash.(hashNode))
}

// Return number of live nodes (not pruned)
// Returns true if the root became hash node
func (t *Trie) TryPrune() (int, bool, error) {
	if t.nodeList != nil {
		// We want t.root to be evaluated on exit, not now
		defer func() { t.relistNodes(t.root) }()
	}
	newRoot, count, unloaded, err := t.tryPrune(t.root)
	if err == nil && unloaded {
		t.root = newRoot
	}
	if _, ok := t.root.(hashNode); ok {
		return count, true, err
	} else {
		return count, false, err
	}
}

func (t *Trie) tryPrune(n node) (newnode node, livecount int, unloaded bool, err error) {
	if n == nil {
		return nil, 0, false, nil
	}
	if _, ok := n.(nodep); !ok {
		return n, 0, false, nil
	}
	if n.unlisted() {
		// Unload the node from cache. All of its subnodes will have a lower or equal
		// cache generation number.
		hash := n.cache()
		// If the node is dirty, we cannot unload, but instead moving to the back of the list
		if hash == nil {
			if t.nodeList != nil {
				if np, ok := n.(nodep); ok {
					// Defering instead of calling to make sure parent nodes are added after their children and not before
					defer t.nodeList.PushToBack(np)
				}
			}
		} else {
			return hash, 0, true, nil
		}
	}
	switch n := (n).(type) {
	case *shortNode:
		newnode, livecount, unloaded, err = t.tryPrune(n.Val)
		nn := n
		if err == nil && unloaded {
			t.touch(n)
			nn = n.copy()
			nn.Val = newnode
		}
		return nn, livecount+1, unloaded, err

	case *duoNode:
		var nc *duoNode
		sumcount := 0
		newnode, livecount, unloaded, err = t.tryPrune(n.child1)
		if err == nil && unloaded {
			if nc == nil {
				nc = n.copy()
			}
			nc.child1 = newnode
		}
		sumcount += livecount
		newnode, livecount, unloaded, err = t.tryPrune(n.child2)
		if err == nil && unloaded {
			if nc == nil {
				nc = n.copy()
			}
			nc.child2 = newnode
		}
		sumcount += livecount
		if nc != nil {
			t.touch(n)
			return nc, sumcount+1, true, err
		} else {
			return n, sumcount+1, false, err
		}

	case *fullNode:
		var nc *fullNode
		sumcount := 0
		for i := 0; i<=16; i++ {
			if n.Children[i] != nil {
				newnode, livecount, unloaded, err = t.tryPrune(n.Children[i])
				if err == nil && unloaded {
					if nc == nil {
						nc = n.copy()
					}
					nc.Children[i] = newnode
				}
				sumcount += livecount
			}
		}
		if nc != nil {
			t.touch(n)
			return nc, sumcount+1, true, err
		} else {
			return n, sumcount+1, false, err
		}
	}
	// Don't count hashNodes and valueNodes
	return n, 0, false, nil
}

func (t *Trie) CountOccupancies(dbr DatabaseReader, blockNr uint64, o []int) {
	if hn, ok := t.root.(hashNode); ok {
		n, err := t.resolveHash(dbr, hn, []byte{}, 0, blockNr)
		if err != nil {
			panic(err)
		}
		t.root = n
	}
	t.countOccupancies(t.root, o)
}

func (t *Trie) countOccupancies(n node, o []int) {
	if n == nil {
		return
	}
	switch n := (n).(type) {
	case *shortNode:
		t.countOccupancies(n.Val, o)
		o[18]++
	case *duoNode:
		t.countOccupancies(n.child1, o)
		t.countOccupancies(n.child2, o)
		o[2]++
	case *fullNode:
		count := 0
		for i := 0; i<=16; i++ {
			if n.Children[i] != nil {
				count++
				t.countOccupancies(n.Children[i], o)
			}
		}
		o[count]++
	}
	return
}

func (t *Trie) hashRoot() (node, error) {
	if t.root == nil {
		return hashNode(emptyRoot.Bytes()), nil
	}
	h := newHasher()
	defer returnHasherToPool(h)
	return h.hash(t.root, true, []byte{})
}
