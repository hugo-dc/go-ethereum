package main

import (
	"bytes"
	"fmt"
	"strings"
	"strconv"
	"flag"
	"runtime/pprof"
	"os"
	"log"
	"sort"
	"io/ioutil"

	"github.com/boltdb/bolt"
	"github.com/wcharczuk/go-chart"
	util "github.com/wcharczuk/go-chart/util"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
)

var emptyCodeHash = crypto.Keccak256(nil)
var emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").Bytes()

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile `file`")

func bucketList(db *bolt.DB) [][]byte {
	bucketList := [][]byte{}
	err := db.View(func(tx *bolt.Tx) error {
		err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if len(name) == 20 || bytes.Equal(name, []byte("AT")) {
				n := make([]byte, len(name))
				copy(n, name)
				bucketList = append(bucketList, n)
			}
			return nil
		})
		return err
	})
	if err != nil {
		panic(fmt.Sprintf("Could view db: %s", err))
	}
	return bucketList
}

// prefixLen returns the length of the common prefix of a and b.
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length {
		length = len(b)
	}
	for ; i < length; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// Transforms b into encoding where only
// 7 bits of each byte are used to encode the bits of b
// The most significant bit is left empty, for other purposes
func encode8to7(b []byte) []byte {
	// Calculate number of bytes in the output
	bits := 8*len(b)
	outbytes := (bits + 6)/7
	in := make([]byte, outbytes)
	copy(in, b)
	out := make([]byte, outbytes)
	inidx := 0
	for outidx := 0; outidx < outbytes; outidx++ {
		switch (outidx%8) {
		case 0:
			out[outidx] =                             in[inidx]>>1
		case 1:
			out[outidx] = ((in[inidx]&0x1)<<6)    | ((in[inidx+1]>>2)&0x3f)
		case 2:
			out[outidx] = ((in[inidx+1]&0x3)<<5)  | ((in[inidx+2]>>3)&0x1f)
		case 3:
			out[outidx] = ((in[inidx+2]&0x7)<<4)  | ((in[inidx+3]>>4)&0xf)
		case 4:
			out[outidx] = ((in[inidx+3]&0xf)<<3)  | ((in[inidx+4]>>5)&0x7)
		case 5:
			out[outidx] = ((in[inidx+4]&0x1f)<<2) | ((in[inidx+5]>>6)&0x3)
		case 6:
			out[outidx] = ((in[inidx+5]&0x3f)<<1) |  (in[inidx+6]>>7)
		case 7:
			out[outidx] =   in[inidx+6]&0x7f
			inidx += 7
		}
	}
	return out
}

func calcBucketSaving(db *bolt.DB, bucket []byte) int {
	keyCounts := make(map[string]int)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			key := encode8to7(k[:32])
			keyStr := string(key)
			if _, ok := keyCounts[keyStr]; ok {
				keyCounts[keyStr]++
			} else {
				keyCounts[keyStr] = 1
			}
		}
		return nil
	})
	if err != nil {
		panic(fmt.Sprintf("Could view db: %s", err))
	}
	keys := []string{}
	for k, _ := range keyCounts {
		keys = append(keys, k)
	}
	prefixLens := make([]int, len(keys))
	sort.Strings(keys)
	maxLen := 0
	for i, k := range keys {
		if i == 0 {
			continue
		}
		l := prefixLen([]byte(k), []byte(keys[i-1])) + 1
		if l > prefixLens[i-1] {
			prefixLens[i-1] = l
		}
		if l > prefixLens[i] {
			prefixLens[i] = l
		}
		if l > maxLen {
			maxLen = l
		}
	}
	total := 0
	for i, k := range keys {
		c := keyCounts[k]
		p := prefixLens[i]
		currentUsage := 36*c
		nextUsage := 32 + p + 32 + (p+5)*c
		saving := currentUsage - nextUsage
		total += saving
	}
	fmt.Printf("Calculating for bucket: %x, maxLen: %d, count: %d, saving: %d\n", bucket, maxLen, len(keys), total)
	return total
}

func calcSpaceSaving(db *bolt.DB) int {
	total := 0
	bucketList := bucketList(db)
	for _, bucket := range bucketList {
		total += calcBucketSaving(db, bucket)
	}
	return total
}

	
func check(e error) {
    if e != nil {
        panic(e)
    }
}

func parseFloat64(str string) float64 {
	v, _ := strconv.ParseFloat(str, 64)
	return v
}

func readData() (blocks []float64, hours []float64, dbsize []float64, trienodes []float64, heap []float64) {
	err := util.File.ReadByLines("geth.csv", func(line string) error {
		parts := strings.Split(line, ",")
		blocks = append(blocks, parseFloat64(strings.Trim(parts[0], " ")))
		hours = append(hours, parseFloat64(strings.Trim(parts[1], " ")))
		dbsize = append(dbsize, parseFloat64(strings.Trim(parts[2], " ")))
		trienodes = append(trienodes, parseFloat64(strings.Trim(parts[3], " ")))
		heap = append(heap, parseFloat64(strings.Trim(parts[4], " ")))
		return nil
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	return
}

func notables() []chart.GridLine {
	return []chart.GridLine{
		{Value: 1.0},
		{Value: 2.0},
		{Value: 3.0},
		{Value: 4.0},
		{Value: 5.0},
	}
}

func days() []chart.GridLine {
	return []chart.GridLine{
		{Value: 24.0},
		{Value: 48.0},
		{Value: 72.0},
	}
}

func mychart() {
	blocks, hours, dbsize, trienodes, heap := readData()
	mainSeries := &chart.ContinuousSeries{
		Name: "Cumulative sync time",
		Style: chart.Style{
			Show:        true,
			StrokeColor: chart.ColorBlue,
			FillColor:   chart.ColorBlue.WithAlpha(100),
		},
		XValues: blocks,
		YValues: hours,
	}
	dbsizeSeries := &chart.ContinuousSeries{
		Name: "Database size",
		Style: chart.Style{
			Show:        true,
			StrokeColor: chart.ColorRed,
		},
		YAxis:   chart.YAxisSecondary,
		XValues: blocks,
		YValues: dbsize,		
	}

	graph1 := chart.Chart{
		Width:  1280,
		Height: 720,
		Background: chart.Style{
			Padding: chart.Box{
				Top: 50,
			},
		},
		YAxis: chart.YAxis{
			Name:      "Elapsed time",
			NameStyle: chart.StyleShow(),
			Style:     chart.StyleShow(),
			TickStyle: chart.Style{
				TextRotationDegrees: 45.0,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%d h", int(v.(float64)))
			},
			GridMajorStyle: chart.Style{
				Show:        true,
				StrokeColor: chart.ColorBlue,
				StrokeWidth: 1.0,
			},
			GridLines: days(),
		},
		YAxisSecondary: chart.YAxis{
			NameStyle: chart.StyleShow(),
			Style: chart.StyleShow(),
			TickStyle: chart.Style{
				TextRotationDegrees: 45.0,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%d G", int(v.(float64)))
			},
		},
		XAxis: chart.XAxis{
			Name: "Blocks, million",
			Style: chart.Style{
				Show: true,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%.3fm", v.(float64))
			},
			GridMajorStyle: chart.Style{
				Show:        true,
				StrokeColor: chart.ColorAlternateGray,
				StrokeWidth: 1.0,
			},
			GridLines: notables(),
		},
		Series: []chart.Series{
			mainSeries,
			dbsizeSeries,
		},
	}

	graph1.Elements = []chart.Renderable{chart.LegendThin(&graph1)}

	buffer := bytes.NewBuffer([]byte{})
	err := graph1.Render(chart.PNG, buffer)
	check(err)
	err = ioutil.WriteFile("chart1.png", buffer.Bytes(), 0644)
    check(err)

	heapSeries := &chart.ContinuousSeries{
		Name: "Allocated heap",
		Style: chart.Style{
			Show:        true,
			StrokeColor: chart.ColorYellow,
			FillColor:   chart.ColorYellow.WithAlpha(100),
		},
		XValues: blocks,
		YValues: heap,
	}
	trienodesSeries := &chart.ContinuousSeries{
		Name: "Trie nodes",
		Style: chart.Style{
			Show:        true,
			StrokeColor: chart.ColorGreen,
		},
		YAxis:   chart.YAxisSecondary,
		XValues: blocks,
		YValues: trienodes,		
	}
	graph2 := chart.Chart{
		Width:  1280,
		Height: 720,
		Background: chart.Style{
			Padding: chart.Box{
				Top: 50,
			},
		},
		YAxis: chart.YAxis{
			Name:      "Allocated heap",
			NameStyle: chart.StyleShow(),
			Style:     chart.StyleShow(),
			TickStyle: chart.Style{
				TextRotationDegrees: 45.0,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%.1f G", v.(float64))
			},
			GridMajorStyle: chart.Style{
				Show:        true,
				StrokeColor: chart.ColorYellow,
				StrokeWidth: 1.0,
			},
			GridLines: days(),
		},
		YAxisSecondary: chart.YAxis{
			NameStyle: chart.StyleShow(),
			Style: chart.StyleShow(),
			TickStyle: chart.Style{
				TextRotationDegrees: 45.0,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%d m", int(v.(float64)))
			},
		},
		XAxis: chart.XAxis{
			Name: "Blocks, million",
			Style: chart.Style{
				Show: true,
			},
			ValueFormatter: func(v interface{}) string {
				return fmt.Sprintf("%.3fm", v.(float64))
			},
			GridMajorStyle: chart.Style{
				Show:        true,
				StrokeColor: chart.ColorAlternateGray,
				StrokeWidth: 1.0,
			},
			GridLines: notables(),
		},
		Series: []chart.Series{
			heapSeries,
			trienodesSeries,
		},
	}

	graph2.Elements = []chart.Renderable{chart.LegendThin(&graph2)}
	buffer.Reset()
	err = graph2.Render(chart.PNG, buffer)
	check(err)
	err = ioutil.WriteFile("chart2.png", buffer.Bytes(), 0644)
    check(err)
}

func accountSavings(db *bolt.DB) (int,int) {
	emptyRoots := 0
	emptyCodes := 0
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("AT"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if bytes.Index(v, emptyRoot) != -1 {
				emptyRoots++
			}
			if bytes.Index(v, emptyCodeHash) != -1 {
				emptyCodes++
			}
		}
		return nil
	})
	return emptyRoots, emptyCodes
}

func allBuckets(db *bolt.DB) [][]byte {
	bucketList := [][]byte{}
	err := db.View(func(tx *bolt.Tx) error {
		err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			n := make([]byte, len(name))
			copy(n, name)
			bucketList = append(bucketList, n)
			return nil
		})
		return err
	})
	if err != nil {
		panic(fmt.Sprintf("Could view db: %s", err))
	}
	return bucketList
}

func bucketStats(db *bolt.DB) {
	bucketList := allBuckets(db)
	storageStats := new(bolt.BucketStats)
	fmt.Printf(",BranchPageN,BranchOverflowN,LeafPageN,LeafOverflowN,KeyN,Depth,BranchAlloc,BranchInuse,LeafAlloc,LeafInuse,BucketN,InlineBucketN,InlineBucketInuse\n")
	db.View(func (tx *bolt.Tx) error {
		for _, bucket := range bucketList {
			b := tx.Bucket(bucket)
			bs := b.Stats()
			if len(bucket) == 20 {
				storageStats.Add(bs)
			} else {
				fmt.Printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", string(bucket),
					bs.BranchPageN,bs.BranchOverflowN,bs.LeafPageN,bs.LeafOverflowN,bs.KeyN,bs.Depth,bs.BranchAlloc,bs.BranchInuse,
					bs.LeafAlloc,bs.LeafInuse,bs.BucketN,bs.InlineBucketN,bs.InlineBucketInuse)
			}
		}
		return nil
	})
	bs := *storageStats
	fmt.Printf("%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", "Contract Storage",
		bs.BranchPageN,bs.BranchOverflowN,bs.LeafPageN,bs.LeafOverflowN,bs.KeyN,bs.Depth,bs.BranchAlloc,bs.BranchInuse,
		bs.LeafAlloc,bs.LeafInuse,bs.BucketN,bs.InlineBucketN,bs.InlineBucketInuse)
}

func main() {
	flag.Parse()
    if *cpuprofile != "" {
        f, err := os.Create(*cpuprofile)
        if err != nil {
            log.Fatal("could not create CPU profile: ", err)
        }
        if err := pprof.StartCPUProfile(f); err != nil {
            log.Fatal("could not start CPU profile: ", err)
        }
        defer pprof.StopCPUProfile()
    }
	db, err := bolt.Open("/home/akhounov/.ethereum/geth/chaindata", 0600, &bolt.Options{ReadOnly: true})
 	if err != nil {
 		panic(fmt.Sprintf("Could not open file: %s", err))
 	}
 	defer db.Close()
 	bucketStats(db)
}

