// Copyright 2015 The go-ethereum Authors
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
	"bytes"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// NewStateSync create a new state trie download scheduler.
func NewStateSync(root common.Hash, database trie.DatabaseReader) *trie.TrieSync {
	var syncer *trie.TrieSync
	callback := func(leaf []byte, parent common.Hash) error {
		var obj Account
		if err := rlp.Decode(bytes.NewReader(leaf), &obj); err != nil {
			return err
		}
		
		log.Info("core/state/sync.go NewStateSync leaf callback.", "Account obj", obj)
		
		// FIXME: This is broken - we do not know the account's address at this point
		//syncer.AddSubTrie([]byte{}, obj.Root, 64, parent, nil)
		//syncer.AddRawEntry([]byte{}, common.BytesToHash(obj.CodeHash), 64, parent)

		// we want it.Key = it.nodeIt.LeafKey()
		/*
		func (it *nodeIterator) LeafKey() []byte {
			if len(it.stack) > 0 {
				if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
					return hexToKeybytes(it.path)
				}
			}
		*/
		//log.Info("core/state/sync.go NewStateSync leaf callback.", "parent.Bytes", parent.Bytes())
		log.Info("core/state/sync.go NewStateSync leaf callback.", "parent.hash", parent)

		// the storage trie is supposed to have the address of the account as the prefix
		// use addrHash as the bucket instead crypto.Keccak256Hash(address[:]).Bytes()

		//syncer.AddSubTrie(StorageBucket, obj.Root, 64, parent, nil)

		//syncer.AddRawEntry(CodeBucket, common.BytesToHash(obj.CodeHash), 64, parent)
		return nil
	}
	log.Debug("core/state/sync.go NewStateSync calling NewTrieSync.", "root", root, "bucket", AccountsBucket)
	syncer = trie.NewTrieSync(AccountsBucket, root, database, callback)
	return syncer
}
