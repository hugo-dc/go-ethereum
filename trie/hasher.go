// Copyright 2016 The go-ethereum Authors
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

package trie

import (
	"bytes"
	"hash"
	"sync"

	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
)

var DepthBucketPrefix = []byte("Depth")
var AccountsDepthBucket = []byte("DepthAT")
var BlockPtrBucket = []byte("BlkPtr")

type hasher struct {
	tmp            *bytes.Buffer
	sha            hash.Hash
}

// hashers live in a global pool.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return &hasher{tmp: new(bytes.Buffer), sha: sha3.NewKeccak256()}
	},
}

func newHasher() *hasher {
	h := hasherPool.Get().(*hasher)
	return h
}

func returnHasherToPool(h *hasher) {
	hasherPool.Put(h)
}

// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
func (h *hasher) hash(n node, force bool, key []byte) (node, error) {
	// If we're not storing the node, just hashing, use available cached data
	if hash := n.cache(); hash != nil {
		return hash, nil
	}
	// Trie not processed yet or needs storage, walk the children
	collapsed, err := h.hashChildren(n, key)
	if err != nil {
		return hashNode{}, err
	}
	hashed, err := h.store(collapsed, force)
	if err != nil {
		return hashNode{}, err
	}
	// Cache the hash of the node for later reuse and remove
	// the dirty flag in commit mode. It's fine to assign these values directly
	// without copying the node first because hashChildren copies it.
	cachedHash, _ := hashed.(hashNode)
	if np, ok := n.(nodep); ok {
		np.setcache(cachedHash)
	}
	return hashed, nil
}

// hashChildren replaces the children of a node with their hashes if the encoded
// size of the child is larger than a hash, returning the collapsed node as well
// as a replacement for the original node with the child hashes cached in.
func (h *hasher) hashChildren(original node, key []byte) (node, error) {
	var err error

	switch n := original.(type) {
	case *shortNode:
		// Hash the short node's child, caching the newly hashed subtree
		collapsed := n.copy()
		nKey := compactToHex(n.Key)
		collapsed.Key = n.Key

		if _, ok := n.Val.(valueNode); !ok {
			collapsed.Val, err = h.hash(n.Val, false, concat(key, nKey...))
			if err != nil {
				return original, err
			}
		}
		if collapsed.Val == nil {
			collapsed.Val = valueNode(nil) // Ensure that nil children are encoded as empty strings.
		}
		return collapsed, nil

	case *duoNode:
		i1, i2 := n.childrenIdx()
		collapsed := n.copy()
		collapsed.child1, err = h.hash(n.child1, false, concat(key, i1))
		if err != nil {
			return original, err
		}
		collapsed.child2, err = h.hash(n.child2, false, concat(key, i2))
		if err != nil {
			return original, err
		}
		return collapsed, nil

	case *fullNode:
		// Hash the full node's children, caching the newly hashed subtrees
		collapsed := n.copy()

		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				collapsed.Children[i], err = h.hash(n.Children[i], false, concat(key, byte(i)))
				if err != nil {
					return original, err
				}
			} else {
				collapsed.Children[i] = valueNode(nil) // Ensure that nil children are encoded as empty strings.
			}
		}
		if collapsed.Children[16] == nil {
			collapsed.Children[16] = valueNode(nil)
		}
		return collapsed, nil

	default:
		// Value and hash nodes don't have children so they're left as were
		return n, nil
	}
}

func EncodeAsValue(data []byte) ([]byte, error) {
	tmp := new(bytes.Buffer)
	err := rlp.Encode(tmp, valueNode(data))
	if err != nil {
		return nil, err
	}
	return tmp.Bytes(), nil
}

func (h *hasher) store(n node, force bool) (node, error) {
	// Don't store hashes or empty nodes.
	if hash, isHash := n.(hashNode); n == nil || isHash {
		return hash, nil
	}
	// Generate the RLP encoding of the node
	h.tmp.Reset()
	if err := rlp.Encode(h.tmp, n); err != nil {
		panic("encode error: " + err.Error())
	}

	if h.tmp.Len() < 32 && !force {
		return n, nil // Nodes smaller than 32 bytes are stored inside their parent
	}

	h.sha.Reset()
	h.sha.Write(h.tmp.Bytes())
	hbytes := h.sha.Sum(nil)
	hbcopy := make([]byte, len(hbytes))
	copy(hbcopy, hbytes)
	hash := hashNode(hbcopy)
	return hash, nil
}
