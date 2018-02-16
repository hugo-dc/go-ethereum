// Copyright 2017 The go-ethereum Authors
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

package state

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
)

// Trie cache generation limit after which to evic trie nodes from memory.
var MaxTrieCacheGen = uint32(4*1024*1024)

var AccountsBucket = []byte("AT")
var CodeBucket = []byte("CODE")

const (
	// Number of past tries to keep. This value is chosen such that
	// reasonable chain reorg depths will hit an existing trie.
	maxPastTries = 12

	// Number of codehash->size associations to keep.
	codeSizeCacheSize = 100000
)

// Database wraps access to tries and contract code.
type Database interface {
	// Accessing tries:
	// OpenTrie opens the main account trie.
	// OpenStorageTrie opens the storage trie of an account.
	OpenTrie(root common.Hash) (Trie, error)
	OpenStorageTrie(addr common.Address, root common.Hash) (Trie, error)
	// Accessing contract code:
	ContractCode(addrHash, codeHash common.Hash) ([]byte, error)
	ContractCodeSize(addrHash, codeHash common.Hash) (int, error)
	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(Trie) Trie
	TrieDb() ethdb.Getter
}

// Trie is a Ethereum Merkle Trie.
type Trie interface {
	TryGet(dbr trie.DatabaseReader, key []byte, blockNr uint64) ([]byte, error)
	TryUpdate(dbr trie.DatabaseReader, key, value []byte, blockNr uint64) error
	TryDelete(dbr trie.DatabaseReader, key []byte, blockNr uint64) error
	CommitPreimages(dbw trie.DatabaseWriter) error
	Hash() common.Hash
	NodeIterator(dbr trie.DatabaseReader, startKey []byte, blockNr uint64) trie.NodeIterator
	HashKey([]byte) []byte
	GetKey(trie.DatabaseReader, []byte) []byte // TODO(fjl): remove this when SecureTrie is removed
	PrintTrie()
	TryPrune() (int, bool, error)
	CountOccupancies(dbr trie.DatabaseReader, blockNr uint64, o []int)
	MakeListed(*trie.List)
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use and retains cached trie nodes in memory.
func NewDatabase(db ethdb.Getter) Database {
	csc, _ := lru.New(codeSizeCacheSize)
	return &cachingDB{db: db, codeSizeCache: csc}
}

type cachingDB struct {
	db            ethdb.Getter
	codeSizeCache *lru.Cache
}

func (db *cachingDB) OpenTrie(root common.Hash) (Trie, error) {
	return trie.NewSecure(root, AccountsBucket)
}

func (db *cachingDB) OpenStorageTrie(addr common.Address, root common.Hash) (Trie, error) {
	return trie.NewSecure(root, addr[:])
}

func (db *cachingDB) CopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.SecureTrie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

func (db *cachingDB) ContractCode(addrHash, codeHash common.Hash) ([]byte, error) {
	code, err := db.db.Get(CodeBucket, codeHash[:])
	if err == nil {
		db.codeSizeCache.Add(codeHash, len(code))
	}
	return code, err
}

func (db *cachingDB) ContractCodeSize(addrHash, codeHash common.Hash) (int, error) {
	if cached, ok := db.codeSizeCache.Get(codeHash); ok {
		return cached.(int), nil
	}
	code, err := db.ContractCode(addrHash, codeHash)
	if err == nil {
		db.codeSizeCache.Add(codeHash, len(code))
	}
	return len(code), err
}

func (db *cachingDB) TrieDb() ethdb.Getter {
	return db.db
}

