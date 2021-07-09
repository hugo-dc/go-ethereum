package codetrie

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"

	//"fmt"

	sszlib "github.com/ferranbt/fastssz"

	"github.com/ethereum/go-ethereum/codetrie/ssz"
	"github.com/ethereum/go-ethereum/common"
)

type CMStats struct {
	NumContracts int
	ProofSize    int
	CodeSize     int
	ProofStats   *ssz.ProofStats
	RLPStats     *ssz.RLPStats
}

func NewCMStats() *CMStats {
	return &CMStats{
		ProofStats: &ssz.ProofStats{},
		RLPStats:   &ssz.RLPStats{},
	}
}

type ContractBag struct {
	contracts map[common.Hash]*Contract
	// TODO: remove
	LargeInitCodes map[common.Hash]int
}

func NewContractBag() *ContractBag {
	return &ContractBag{
		contracts:      make(map[common.Hash]*Contract),
		LargeInitCodes: make(map[common.Hash]int),
	}
}

func (b *ContractBag) Get(codeHash common.Hash, code []byte) *Contract {
	if c, ok := b.contracts[codeHash]; ok {
		return c
	}

	c := NewContract(code)
	b.contracts[codeHash] = c
	return c
}

func (b *ContractBag) AddLargeInit(codeHash common.Hash, size int) {
	b.LargeInitCodes[codeHash] = size
}

func logString(fname string, data string) {
	proofFile, err := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return
	}

	defer proofFile.Close()
	if _, err := proofFile.WriteString(data); err != nil {
		return
	}
}

func extractChunksData(chunks []int) string {
	result := ""

	for _, c := range chunks {
		result += string(c) + ","
	}

	return result
}

func extractBaselineData(p *sszlib.Multiproof) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func extractSlimData(cp *sszlib.CompressedMultiproof) string {
	b, err := json.Marshal(cp)
	if err != nil {
		return ""
	}
	return string(b)
}

func extractBaselineRLP(p *ssz.Multiproof) string {
	rlp, err := p.Serialize()
	if err != nil {
		return ""
	}

	return hex.EncodeToString(rlp)
}

func extractSlimRLP(cp *ssz.CompressedMultiproof) string {
	rlp, err := cp.Serialize()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(rlp)
}

func (b *ContractBag) Stats() (*CMStats, error) {
	stats := NewCMStats()
	stats.NumContracts = len(b.contracts)
	for h, c := range b.contracts {
		stats.CodeSize += c.CodeSize()
		rawProof, err := c.Prove()
		if err != nil {
			return nil, err
		}

		cHash := hex.EncodeToString(h[:])
		slimProof := rawProof.Compress()

		// Convert Proof into a Serializable format
		p := ssz.NewMultiproof(rawProof)
		cp := ssz.NewCompressedMultiproof(slimProof)

		// Log Bytecode
		logString(cHash+"_code.txt", hex.EncodeToString(c.Code()))

		// Log Touched Chunks
		chunksString := extractChunksData(c.TouchedChunks())
		logString(cHash+"_chunks.txt", chunksString)

		// Proof Data
		baselineData := extractBaselineData(rawProof)
		logString(cHash+"_baseline.txt", baselineData)

		slimData := extractSlimData(slimProof)
		logString(cHash+"_slim.txt", slimData)

		// Proof Data as RLP
		baselineRlp := extractBaselineRLP(p)
		logString(cHash+"_rlp_baseline.txt", baselineRlp)

		slimRlp := extractSlimRLP(cp)
		logString(cHash+"_rlp_slim.txt", slimRlp)

		//fmt.Println("contract:")
		//fmt.Println("\tcode: ", hex.EncodeToString(c.Code()))
		//fmt.Println("\ttouchedChunks: ", c.TouchedChunks())
		//fmt.Println("proof: ")
		//fmt.Println("\tIndices: ", rawProof.Indices)
		//fmt.Println("\tLeaves: ", len(rawProof.Leaves))

		/*
			for _, leaf := range rawProof.Leaves {
				fmt.Println(hex.EncodeToString(leaf))
			}
		*/
		//fmt.Println("\tHashes: ", len(rawProof.Hashes))
		/*
			for _, hash := range rawProof.Hashes {
				fmt.Println(hex.EncodeToString(hash))
			}
		*/

		ps := cp.ProofStats()
		stats.ProofStats.Add(ps)

		rs, err := ssz.NewRLPStats(p, cp)
		if err != nil {
			return nil, err
		}
		stats.RLPStats.Add(rs)
	}
	stats.ProofSize = stats.ProofStats.Sum()
	return stats, nil
}

type Contract struct {
	code          []byte
	touchedChunks map[int]bool
}

func NewContract(code []byte) *Contract {
	touchedChunks := make(map[int]bool)
	return &Contract{code: code, touchedChunks: touchedChunks}
}

func (c *Contract) TouchPC(pc int) error {
	if pc >= len(c.code) {
		return errors.New("PC to touch exceeds bytecode length")
	}

	cid := pc / 32
	c.touchedChunks[cid] = true

	return nil
}

func (c *Contract) TouchRange(from, to int) error {
	if from >= to {
		return errors.New("Invalid range")
	}
	if to >= len(c.code) {
		return errors.New("PC to touch exceeds bytecode length")
	}

	fcid := from / 32
	tcid := to / 32
	for i := fcid; i < tcid+1; i++ {
		c.touchedChunks[i] = true
	}

	return nil
}

func (c *Contract) CodeSize() int {
	return len(c.code)
}

func (c *Contract) Code() []byte {
	return c.code
}

func (c *Contract) TouchedChunks() []int {
	indices := make([]int, 0, len(c.touchedChunks))
	for k := range c.touchedChunks {
		indices = append(indices, k)
	}
	return indices
}

func (c *Contract) Prove() (*sszlib.Multiproof, error) {
	tree, err := GetSSZTree(c.code, 32)
	if err != nil {
		return nil, err
	}

	// ChunksLen and metadata fields
	mdIndices := []int{7, 8, 9, 10}

	touchedChunks := c.sortedTouchedChunks()
	chunkIndices := make([]int, 0, len(touchedChunks)*2)
	for k := range touchedChunks {
		// 6144 is global index for first chunk's node
		// Each chunk node has two children: FIO, code
		chunkIdx := 6144 + k
		chunkIndices = append(chunkIndices, chunkIdx*2)
		chunkIndices = append(chunkIndices, chunkIdx*2+1)
	}

	p, err := tree.ProveMulti(append(mdIndices, chunkIndices...))
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (c *Contract) sortedTouchedChunks() []int {
	touched := make([]int, 0, len(c.touchedChunks))
	for k := range c.touchedChunks {
		touched = append(touched, k)
	}
	sort.Ints(touched)
	return touched
}
