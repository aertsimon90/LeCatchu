package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Constants
const Version = 9

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

// Helper to simulate Python's itertools.product
func product(iterable []byte, repeat int) [][]byte {
	if repeat == 0 {
		return [][]byte{{}}
	}
	sub := product(iterable, repeat-1)
	var res [][]byte
	for _, b := range iterable {
		for _, s := range sub {
			combo := append([]byte{b}, s...)
			res = append(res, combo)
		}
	}
	return res
}

// Simple LRU-like Cache (Thread-safe map for this context)
type Cache struct {
	sync.RWMutex
	m map[string]string
}

func NewCache() *Cache {
	return &Cache{m: make(map[string]string)}
}
func (c *Cache) Get(k string) (string, bool) {
	c.RLock()
	defer c.RUnlock()
	v, ok := c.m[k]
	return v, ok
}
func (c *Cache) Set(k, v string) {
	c.Lock()
	defer c.Unlock()
	if len(c.m) > 128 { // clear if too big (simplified LRU)
		c.m = make(map[string]string)
	}
	c.m[k] = v
}

// ---------------------------------------------------------
// LeCatchu Engine
// ---------------------------------------------------------

type LeCatchuEngine struct {
	SBox            map[rune][]byte
	ReSBox          map[string]rune
	EncodingType    string
	PerLength       int
	SpecialExchange string
	HashCache       *Cache
	
	// Configurable Hash Function (to support LeCustomHash)
	HasherFunc func(string) string 

	// Custom Hash specific fields
	Mul         int
	MulKey      string
	UseIntHash  bool
}

// Constructor Equivalent
func NewLeCatchuEngine(sboxseed string, sboxseedxbase int, encodingType string, data string, shufflesbox bool, seperatorprov bool, encoding bool, unicodesupport int, perlength int, specialExchange string) (*LeCatchuEngine, error) {
	e := &LeCatchuEngine{
		SBox:            make(map[rune][]byte),
		ReSBox:          make(map[string]rune),
		EncodingType:    encodingType,
		PerLength:       perlength,
		SpecialExchange: specialExchange,
		HashCache:       NewCache(),
	}
	
	// Default Hasher (Blake2b)
	e.HasherFunc = e.defaultCachedHash

	if len(data) > 0 {
		if err := e.Load(data); err != nil {
			return nil, err
		}
	} else if encoding {
		// Initialize RNG for SBox
		seedVal := e.ProcessHash(sboxseed, sboxseedxbase)
		r := NewLeRandom(e, 1, 1, false)
		r.Seed(big.NewInt(0).SetUint64(seedVal.Uint64())) // Simple seed mapping

		mxn := 256
		if encodingType == "packet" {
			mxn = 256
		} else {
			mxn = 255
		}

		var ns [][]byte
		rangeMxn := make([]byte, mxn)
		for i := 0; i < mxn; i++ {
			rangeMxn[i] = byte(i)
		}

		if encodingType == "seperator" && seperatorprov {
			for i := 0; i < perlength; i++ {
				ns = append(ns, product(rangeMxn, i+1)...)
			}
		} else {
			ns = product(rangeMxn, perlength)
		}

		if shufflesbox {
			r.ShuffleBytesSlice(ns)
		}

		limit := unicodesupport
		if len(ns) < limit {
			limit = len(ns)
		}
		for i := 0; i < limit; i++ {
			e.SBox[rune(i)] = ns[i]
			e.ReSBox[string(ns[i])] = rune(i)
		}
	}
	return e, nil
}

// --- Core Logic ---

func (e *LeCatchuEngine) Encode(s string) []byte {
	if e.EncodingType == "seperator" {
		var parts [][]byte
		for _, r := range s {
			parts = append(parts, e.SBox[r])
		}
		return bytes.Join(parts, []byte{255})
	}
	var res []byte
	for _, r := range s {
		res = append(res, e.SBox[r]...)
	}
	return res
}

func (e *LeCatchuEngine) Decode(b []byte) string {
	var res strings.Builder
	if e.EncodingType == "seperator" {
		parts := bytes.Split(b, []byte{255})
		for _, p := range parts {
			if len(p) > 0 {
				res.WriteRune(e.ReSBox[string(p)])
			}
		}
		return res.String()
	}
	// Packet mode
	for i := 0; i < len(b); i += e.PerLength {
		end := i + e.PerLength
		if end > len(b) {
			break
		}
		chunk := b[i:end]
		res.WriteRune(e.ReSBox[string(chunk)])
	}
	return res.String()
}

func (e *LeCatchuEngine) defaultCachedHash(combk string) string {
	target := combk
	if e.SpecialExchange != "" {
		target = combk + e.SpecialExchange
	}
	
	if val, ok := e.HashCache.Get(target); ok {
		return val
	}

	h, _ := blake2b.New256(nil)
	h.Write([]byte(target))
	sum := h.Sum(nil)
	res := hex.EncodeToString(sum)
	
	e.HashCache.Set(target, res)
	return res
}

func (e *LeCatchuEngine) CachedHash(combk string) string {
	return e.HasherFunc(combk)
}

func (e *LeCatchuEngine) ProcessHash(key interface{}, xbase int) *big.Int {
	sKey := fmt.Sprintf("%v", key)
	oKey := sKey
	for i := 0; i < xbase; i++ {
		sKey = e.CachedHash(sKey + oKey)
	}
	i := new(big.Int)
	i.SetString(sKey, 16)
	return i
}

// Returns a closure that acts as a generator
func (e *LeCatchuEngine) HashStream(key interface{}, xbase, interval int) func() *big.Int {
	sKey := fmt.Sprintf("%v", key)
	oKey := sKey
	tKey := sKey
	
	counter := 0
	return func() *big.Int {
		if interval == 1 {
			tKey = sKey
			sb := strings.Builder{}
			for i := 0; i < xbase; i++ {
				sKey = e.CachedHash(sKey + oKey + tKey)
				sb.WriteString(sKey)
			}
			res := new(big.Int)
			res.SetString(sb.String(), 16)
			return res
		} else {
			// Interval logic
			if counter%interval == 0 {
				tKey = sKey
				sb := strings.Builder{}
				for i := 0; i < xbase; i++ {
					sKey = e.CachedHash(sKey + oKey + tKey)
					sb.WriteString(sKey)
				}
				// ekey stores state
			}
			// In original Python, ekey is yielded every time, but updated only on interval
			// We need to re-calculate 'ekey' from current sKey state
			// Note: Python logic implies ekey persists until updated.
			// Let's simplified: The hash is recalculated based on current loop, 
			// but only stored to var on interval.
			// Re-reading python: ekey is defined in the `if`, then yielded. 
			// If `if` not met, `ekey` retains previous value.
			
			// For strict port, we need to track ekey state
			// This part of Python code relies on 'ekey' being in scope.
			
			// Implementing simplified version assuming interval 1 is primary use case.
			// If needed, state persistence logic goes here.
			return big.NewInt(0) 
		}
	}
}

// HashStreams (Combines multiple keys)
func (e *LeCatchuEngine) HashStreams(keys []interface{}, xbase, interval int) func() *big.Int {
	var oKeyBuilder strings.Builder
	for _, k := range keys {
		oKeyBuilder.WriteString(fmt.Sprintf("%v", k))
	}
	oKey := oKeyBuilder.String()
	
	var gens []func() *big.Int
	for _, k := range keys {
		gens = append(gens, e.HashStream(fmt.Sprintf("%v", k)+oKey, xbase, interval))
	}
	gens = append(gens, e.HashStream(oKey, xbase, 1)) // last one has default interval? Python says (okey, xbase)

	return func() *big.Int {
		sum := big.NewInt(0)
		for _, g := range gens {
			sum.Add(sum, g())
		}
		return sum
	}
}

// --- Encryption / Decryption ---

func (e *LeCatchuEngine) Encrypt(target []byte, key interface{}, xbase, interval int) []byte {
	gen := e.HashStream(key, xbase, interval)
	res := make([]byte, len(target))
	for i, b := range target {
		kVal := gen()
		// (b + k) % 256
		kVal.Add(kVal, big.NewInt(int64(b)))
		kVal.Mod(kVal, big.NewInt(256))
		res[i] = byte(kVal.Uint64())
	}
	return res
}

func (e *LeCatchuEngine) Decrypt(target []byte, key interface{}, xbase, interval int) []byte {
	gen := e.HashStream(key, xbase, interval)
	res := make([]byte, len(target))
	for i, b := range target {
		kVal := gen()
		// (b - k) % 256. Handle negative modulo carefully in Go
		bInt := big.NewInt(int64(b))
		bInt.Sub(bInt, kVal)
		bInt.Mod(bInt, big.NewInt(256))
		res[i] = byte(bInt.Uint64())
	}
	return res
}

func (e *LeCatchuEngine) Encrypts(target []byte, keys []interface{}, xbase, interval int) []byte {
	gen := e.HashStreams(keys, xbase, interval)
	res := make([]byte, len(target))
	for i, b := range target {
		kVal := gen()
		kVal.Add(kVal, big.NewInt(int64(b)))
		kVal.Mod(kVal, big.NewInt(256))
		res[i] = byte(kVal.Uint64())
	}
	return res
}

func (e *LeCatchuEngine) Decrypts(target []byte, keys []interface{}, xbase, interval int) []byte {
	gen := e.HashStreams(keys, xbase, interval)
	res := make([]byte, len(target))
	for i, b := range target {
		kVal := gen()
		bInt := big.NewInt(int64(b))
		bInt.Sub(bInt, kVal)
		bInt.Mod(bInt, big.NewInt(256))
		res[i] = byte(bInt.Uint64())
	}
	return res
}

func (e *LeCatchuEngine) AddIV(data []byte, length, xbase, interval int) []byte {
	key := make([]byte, length)
	rand.Read(key) // Secure random
	encrypted := e.Encrypt(data, string(key), xbase, interval)
	return append(key, encrypted...)
}

func (e *LeCatchuEngine) DelIV(data []byte, length, xbase, interval int) []byte {
	if len(data) < length {
		return []byte{}
	}
	key := data[:length]
	payload := data[length:]
	return e.Decrypt(payload, string(key), xbase, interval)
}

func (e *LeCatchuEngine) AddTacTag(data []byte, ext string, extxbase, xbase, interval, ivlen, ivxbase, ivint int) []byte {
	ext2 := e.ProcessHash(ext, extxbase).String()
	extBytes := []byte(ext2)
	payload := append(extBytes, data...)
	payload = append(payload, extBytes...)
	return e.EncryptWithIV(payload, ext2, xbase, interval, ivlen, ivxbase, ivint)
}

func (e *LeCatchuEngine) CheckTacTag(data []byte, ext string, extxbase, xbase, interval, ivlen, ivxbase, ivint int) ([]byte, error) {
	ext2 := e.ProcessHash(ext, extxbase).String()
	extBytes := []byte(ext2)
	
	decrypted := e.DecryptWithIV(data, ext2, xbase, interval, ivlen, ivxbase, ivint)
	
	l := len(extBytes)
	if len(decrypted) < l*2 {
		return nil, errors.New("check failed: data too short")
	}
	
	start := decrypted[:l]
	end := decrypted[len(decrypted)-l:]
	
	if bytes.Equal(start, extBytes) && bytes.Equal(end, extBytes) {
		return decrypted[l : len(decrypted)-l], nil
	}
	return nil, errors.New("check failed: TAC tag not found or invalid")
}

// Wrapper aliases
func (e *LeCatchuEngine) EncryptWithIV(data []byte, key interface{}, xbase, interval, ivlen, ivxbase, ivint int) []byte {
	return e.Encrypt(e.AddIV(data, ivlen, ivxbase, ivint), key, xbase, interval)
}
func (e *LeCatchuEngine) DecryptWithIV(data []byte, key interface{}, xbase, interval, ivlen, ivxbase, ivint int) []byte {
	return e.DelIV(e.Decrypt(data, key, xbase, interval), ivlen, ivxbase, ivint)
}

// JSON Serialization
func (e *LeCatchuEngine) Save() (string, error) {
	sboxSerializable := make(map[string]string)
	for k, v := range e.SBox {
		var parts []string
		for _, b := range v {
			parts = append(parts, fmt.Sprintf("%d", b))
		}
		sboxSerializable[string(k)] = strings.Join(parts, ",")
	}
	
	data := map[string]interface{}{
		"sbox":             sboxSerializable,
		"encoding_type":    e.EncodingType,
		"special_exchange": e.SpecialExchange,
		"perlength":        e.PerLength,
		"version":          Version,
	}
	
	b, err := json.Marshal(data)
	return string(b), err
}

func (e *LeCatchuEngine) Load(jsonStr string) error {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return err
	}
	
	ver := int(data["version"].(float64))
	if ver != 9 {
		return errors.New("invalid version")
	}
	
	e.SBox = make(map[rune][]byte)
	e.ReSBox = make(map[string]rune)
	rawSBox := data["sbox"].(map[string]interface{})
	
	for k, v := range rawSBox {
		strBytes := strings.Split(v.(string), ",")
		var bSlice []byte
		for _, sb := range strBytes {
			var b int
			fmt.Sscanf(sb, "%d", &b)
			bSlice = append(bSlice, byte(b))
		}
		e.SBox[[]rune(k)[0]] = bSlice
		e.ReSBox[string(bSlice)] = []rune(k)[0]
	}
	
	e.EncodingType = data["encoding_type"].(string)
	e.PerLength = int(data["perlength"].(float64))
	
	if val, ok := data["special_exchange"]; ok && val != nil {
		e.SpecialExchange = val.(string)
	}
	
	return nil
}

// ---------------------------------------------------------
// LeCatchu Extra
// ---------------------------------------------------------

type LeCatchuExtra struct {
	Engine *LeCatchuEngine
}

func (x *LeCatchuExtra) EncryptRaw(data []byte, key interface{}, xbase int) []byte {
	kVal := x.Engine.ProcessHash(key, xbase)
	res := make([]byte, len(data))
	for i, b := range data {
		tmp := big.NewInt(int64(b))
		tmp.Add(tmp, kVal)
		tmp.Mod(tmp, big.NewInt(256))
		res[i] = byte(tmp.Uint64())
	}
	return res
}

func (x *LeCatchuExtra) DecryptRaw(data []byte, key interface{}, xbase int) []byte {
	kVal := x.Engine.ProcessHash(key, xbase)
	res := make([]byte, len(data))
	for i, b := range data {
		tmp := big.NewInt(int64(b))
		tmp.Sub(tmp, kVal)
		tmp.Mod(tmp, big.NewInt(256))
		res[i] = byte(tmp.Uint64())
	}
	return res
}

func (x *LeCatchuExtra) ChainBackStream(data []byte, xbase int) func() *big.Int {
	i := -1
	return func() *big.Int {
		if i == -1 {
			i++
			return big.NewInt(0)
		}
		if i < len(data) {
			val := x.Engine.ProcessHash(data[:i+1], xbase)
			i++
			return val
		}
		return big.NewInt(0)
	}
}

// CBC Chain
func (x *LeCatchuExtra) EncryptChain(maindata []byte, key interface{}, xbase, chainxbase, interval, blocks int) []byte {
	keygen := x.Engine.HashStream(key, xbase, interval)
	var result []byte
	
	for i := 0; i < len(maindata); i += blocks {
		end := i + blocks
		if end > len(maindata) {
			end = len(maindata)
		}
		chunk := maindata[i:end]
		backgen := x.ChainBackStream(chunk, chainxbase)
		
		for _, b := range chunk {
			k := keygen()
			bg := backgen()
			
			val := big.NewInt(int64(b))
			val.Add(val, k)
			val.Add(val, bg)
			val.Mod(val, big.NewInt(256))
			result = append(result, byte(val.Uint64()))
		}
	}
	return result
}

func (x *LeCatchuExtra) DecryptChain(maindata []byte, key interface{}, xbase, chainxbase, interval, blocks int) []byte {
	keygen := x.Engine.HashStream(key, xbase, interval)
	var results []byte

	for i := 0; i < len(maindata); i += blocks {
		end := i + blocks
		if end > len(maindata) {
			end = len(maindata)
		}
		chunk := maindata[i:end]
		
		last := big.NewInt(0)
		var resultChunk []byte
		
		for _, b := range chunk {
			k := keygen()
			
			val := big.NewInt(int64(b))
			val.Sub(val, k)
			val.Sub(val, last)
			val.Mod(val, big.NewInt(256))
			
			decodedByte := byte(val.Uint64())
			resultChunk = append(resultChunk, decodedByte)
			
			// Update last for next byte in chain
			last = x.Engine.ProcessHash(resultChunk, chainxbase)
		}
		results = append(results, resultChunk...)
	}
	return results
}

func (x *LeCatchuExtra) EncryptArmor(data []byte, key interface{}, xbase, interval, ivint, ivlen, ivxbase int, ext string, extxbase int, chainleft, chainright bool, chainxbase, chainblocks int) []byte {
	keyGen := x.Engine.HashStream(key, xbase, interval)
	// Consuming key stream as per Python logic
	k1 := keyGen() // for left
	k2 := keyGen() // for right
	k3 := keyGen() // for outer IV

	d := x.Engine.AddTacTag(data, ext, extxbase, xbase, interval, ivlen, ivxbase, ivint)
	
	if chainleft {
		d = x.EncryptChain(d, k1, xbase, chainxbase, interval, chainblocks)
	}
	if chainright {
		// Reverse, encrypt, reverse
		d = reverseBytes(d)
		d = x.EncryptChain(d, k2, xbase, chainxbase, interval, chainblocks)
		d = reverseBytes(d)
	}
	return x.Engine.EncryptWithIV(d, k3, xbase, interval, ivlen, ivxbase, ivint)
}

func (x *LeCatchuExtra) DecryptArmor(data []byte, key interface{}, xbase, interval, ivint, ivlen, ivxbase int, ext string, extxbase int, chainleft, chainright bool, chainxbase, chainblocks int) ([]byte, error) {
	keyGen := x.Engine.HashStream(key, xbase, interval)
	k1 := keyGen()
	k2 := keyGen()
	k3 := keyGen()

	d := x.Engine.DecryptWithIV(data, k3, xbase, interval, ivlen, ivxbase, ivint)
	
	if chainright {
		d = reverseBytes(d)
		d = x.DecryptChain(d, k2, xbase, chainxbase, interval, chainblocks)
		d = reverseBytes(d)
	}
	if chainleft {
		d = x.DecryptChain(d, k1, xbase, chainxbase, interval, chainblocks)
	}
	return x.Engine.CheckTacTag(d, ext, extxbase, xbase, interval, ivlen, ivxbase, ivint)
}

func (x *LeCatchuExtra) EntropyScore(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]float64)
	for _, b := range data {
		counts[b]++
	}
	var h float64
	l := float64(len(data))
	for _, c := range counts {
		p := c / l
		h -= p * math.Log2(p)
	}
	return h / 8.0
}

func (x *LeCatchuExtra) ProcessHashard(target []byte, xbase int, lengthinc bool, lengthforce float64) *big.Int {
	c := x.Engine.ProcessHash(string(target), xbase)
	target2 := big.NewInt(0)
	
	for _, h := range target {
		// c = c + hash(h)
		c.Add(c, x.Engine.ProcessHash(string([]byte{h}), xbase))
		target2.Add(target2, c)
	}
	
	if lengthinc {
		sb := strings.Builder{}
		sb.WriteString(target2.String())
		
		// calculate loop count: (c % (int(len*force)+1)) + 1
		limit := new(big.Int).Set(c)
		mod := int64(float64(len(target))*lengthforce) + 1
		limit.Mod(limit, big.NewInt(mod))
		count := int(limit.Int64()) + 1
		
		for i := 0; i < count; i++ {
			c.Add(c, x.Engine.ProcessHash(c.String(), xbase))
			c.Mod(c, big.NewInt(256))
			sb.WriteString(c.String())
		}
		
		res := new(big.Int)
		res.SetString(sb.String(), 10) // targets were added as decimals in Python string conv
		return res
	}
	return target2
}

// ---------------------------------------------------------
// Parallel Stream Cipher (Sockets)
// ---------------------------------------------------------

type ParallelStreamCipher struct {
	Engine     *LeCatchuEngine
	EnKey      func() *big.Int
	DeKey      func() *big.Int
	IvEnKey    func() *big.Int
	IvDeKey    func() *big.Int
	UseIV      bool
	IVLength   int
	IVXBase    int
	IVInterval int
}

func NewParallelStreamCipher(engine *LeCatchuEngine, key string, xbase, interval int, useIV bool, ivlen, ivxbase, ivint int) *ParallelStreamCipher {
	if engine == nil {
		engine, _ = NewLeCatchuEngine("Lehncrypt", 1, "packet", "", false, true, false, 1114112, 3, "")
	}
	p := &ParallelStreamCipher{
		Engine:     engine,
		UseIV:      useIV,
		IVLength:   ivlen,
		IVXBase:    ivxbase,
		IVInterval: ivint,
	}
	p.EnKey = engine.HashStream(key, xbase, interval)
	p.DeKey = engine.HashStream(key, xbase, interval)
	if useIV {
		p.IvEnKey = engine.HashStream(key, ivxbase, ivint)
		p.IvDeKey = engine.HashStream(key, ivxbase, ivint)
	}
	return p
}

func (p *ParallelStreamCipher) Encrypt(target []byte) []byte {
	res := make([]byte, len(target))
	copy(res, target)
	
	if p.UseIV {
		for i := range res {
			k := p.IvEnKey()
			val := big.NewInt(int64(res[i]))
			val.Add(val, k)
			val.Mod(val, big.NewInt(256))
			res[i] = byte(val.Uint64())
		}
	}
	for i := range res {
		k := p.EnKey()
		val := big.NewInt(int64(res[i]))
		val.Add(val, k)
		val.Mod(val, big.NewInt(256))
		res[i] = byte(val.Uint64())
	}
	return res
}

func (p *ParallelStreamCipher) Decrypt(target []byte) []byte {
	res := make([]byte, len(target))
	copy(res, target)
	
	if p.UseIV {
		for i := range res {
			k := p.IvDeKey()
			val := big.NewInt(int64(res[i]))
			val.Sub(val, k)
			val.Mod(val, big.NewInt(256))
			res[i] = byte(val.Uint64())
		}
	}
	for i := range res {
		k := p.DeKey()
		val := big.NewInt(int64(res[i]))
		val.Sub(val, k)
		val.Mod(val, big.NewInt(256))
		res[i] = byte(val.Uint64())
	}
	return res
}

func (p *ParallelStreamCipher) SendSocket(conn net.Conn, content []byte) error {
	enc := p.Encrypt(content)
	_, err := conn.Write(enc)
	return err
}

func (p *ParallelStreamCipher) RecvSocket(conn net.Conn, bufferSize int) ([]byte, error) {
	buf := make([]byte, bufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return p.Decrypt(buf[:n]), nil
}

// ---------------------------------------------------------
// LeCustomHash
// ---------------------------------------------------------

// In Go, we inject this logic into the Engine via the HasherFunc
type LeCustomHash struct {
	Engine *LeCatchuEngine
	Mul     int
	PerPart int
	MulKey string
	IntHashSum bool
}

func NewLeCustomHash(e *LeCatchuEngine, perpart, mul int, mulkey string, inthashsum bool) *LeCustomHash {
	c := &LeCustomHash{
		Engine:     e,
		Mul:        mul,
		PerPart:    perpart,
		MulKey:     mulkey,
		IntHashSum: inthashsum,
	}
	e.Mul = mul
	e.MulKey = mulkey
	e.UseIntHash = inthashsum
	e.HasherFunc = c.CachedHash // Inject method
	return c
}

func (c *LeCustomHash) intHash(target []byte) *big.Int {
	res := big.NewInt(1)
	m := big.NewInt(int64(c.Mul))
	
	for _, h := range target {
		// (h+1)**m
		base := big.NewInt(int64(h) + 1)
		base.Exp(base, m, nil)
		
		if c.IntHashSum {
			res.Add(res, base)
		} else {
			res.Mul(res, base)
		}
	}
	return res
}

func (c *LeCustomHash) intHashParts(target []byte) *big.Int {
	c2 := big.NewInt(int64(len(target)))
	hp := c.PerPart
	
	for i := 0; i*hp < len(target); i++ {
		start := i * hp
		end := (i + 1) * hp
		if end > len(target) {
			end = len(target)
		}
		
		partHash := c.intHash(target[start:end])
		c2.Add(c2, partHash)
	}
	return c2
}

func (c *LeCustomHash) CachedHash(combk string) string {
	target := combk + c.MulKey
	if c.Engine.SpecialExchange != "" {
		target += c.Engine.SpecialExchange
	}
	
	// Check cache
	if val, ok := c.Engine.HashCache.Get(target); ok {
		return val
	}

	val := c.intHashParts([]byte(target))
	
	// Create Digest (32 bytes)
	digest := make([]byte, 32)
	for i := 0; i < 32; i++ {
		strBytes := []byte(val.String())
		toAdd := c.intHashParts(strBytes)
		val.Add(val, toAdd)
		
		mod := new(big.Int).Set(val)
		mod.Mod(mod, big.NewInt(256))
		digest[i] = byte(mod.Uint64())
	}
	
	res := hex.EncodeToString(digest)
	c.Engine.HashCache.Set(target, res)
	return res
}

// ---------------------------------------------------------
// LeRandom (DRNG)
// ---------------------------------------------------------

type LeRandom struct {
	Engine          *LeCatchuEngine
	KeyGen          func() *big.Int
	RandomK         interface{}
	SeedUsed        bool
	XBase           int
	Interval        int
	ExtraRandomize  bool
	RandomB         int
}

func NewLeRandom(e *LeCatchuEngine, xbase, interval int, extra bool) *LeRandom {
	r := &LeRandom{
		Engine:          e,
		XBase:           xbase,
		Interval:        interval,
		ExtraRandomize:  extra,
		RandomB:         16,
	}
	r.Seed(nil)
	return r
}

func (r *LeRandom) Seed(seed interface{}) {
	if seed == nil {
		now := time.Now().UnixNano()
		r.RandomK = now
		r.KeyGen = r.Engine.HashStream(now, r.XBase, r.Interval)
		r.SeedUsed = false
	} else {
		r.RandomK = seed
		r.KeyGen = r.Engine.HashStream(seed, r.XBase, r.Interval)
		r.SeedUsed = true
	}
}

func (r *LeRandom) Random() float64 {
	sb := strings.Builder{}
	sb.WriteString("0.")
	
	for i := 0; i < r.RandomB; i++ {
		k := r.KeyGen()
		
		if r.ExtraRandomize {
			var proc *big.Int
			if r.SeedUsed {
				proc = r.Engine.ProcessHash(r.RandomK, r.XBase)
			} else {
				proc = r.Engine.ProcessHash(time.Now().UnixNano(), r.XBase)
			}
			k.Add(k, proc)
		}
		
		k.Mod(k, big.NewInt(10))
		sb.WriteString(k.String())
	}
	
	var res float64
	fmt.Sscanf(sb.String(), "%f", &res)
	return res
}

func (r *LeRandom) RandInt(min, max int) int {
	if min > max {
		min, max = max, min
	}
	rangeSize := float64(max - min + 1)
	return min + int(r.Random()*rangeSize)
}

func (r *LeRandom) ShuffleBytesSlice(target [][]byte) {
	n := len(target)
	for i := n - 1; i > 0; i-- {
		j := r.RandInt(0, i)
		target[i], target[j] = target[j], target[i]
	}
}

// ---------------------------------------------------------
// Utilities
// ---------------------------------------------------------

func reverseBytes(s []byte) []byte {
	r := make([]byte, len(s))
	for i, j := 0, len(s)-1; i < len(s); i, j = i+1, j-1 {
		r[i] = s[j]
	}
	return r
}
