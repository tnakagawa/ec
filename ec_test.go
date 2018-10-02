package ec_test

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/tnakagawa/ec"
)

func TestS256K1(t *testing.T) {
	bs, err := ioutil.ReadFile("./secp256k1test.json")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var tests []map[string]string
	err = json.Unmarshal(bs, &tests)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	S256K1 := ec.S256K1
	for _, test := range tests {
		k, ok := new(big.Int).SetString(test["k"], 10)
		if !ok {
			t.Errorf("error SetString %v", test["k"])
			return
		}
		x, ok := new(big.Int).SetString(test["x"], 16)
		if !ok {
			t.Errorf("error SetString %v", test["x"])
			return
		}
		y, ok := new(big.Int).SetString(test["y"], 16)
		if !ok {
			t.Errorf("error SetString %v", test["y"])
			return
		}
		p := S256K1.BaseMul(k)
		if x.Cmp(p.X) != 0 || y.Cmp(p.Y) != 0 {
			t.Errorf("not match %v", k)
			t.Logf("%x,%x", x.Bytes(), y.Bytes())
			t.Logf("%x,%x", p.X.Bytes(), p.Y.Bytes())
			return
		}
	}
}

func TestS256R1(t *testing.T) {
	bs, err := ioutil.ReadFile("./secp256r1test.json")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var tests []map[string]string
	err = json.Unmarshal(bs, &tests)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	S256R1 := ec.S256R1
	for _, test := range tests {
		k, ok := new(big.Int).SetString(test["m"], 10)
		if !ok {
			t.Errorf("error SetString %v", test["m"])
			return
		}
		x, ok := new(big.Int).SetString(test["X"][2:], 16)
		if !ok {
			t.Errorf("error SetString %v", test["X"])
			return
		}
		y, ok := new(big.Int).SetString(test["Y"][2:], 16)
		if !ok {
			t.Errorf("error SetString %v", test["Y"])
			return
		}
		p := S256R1.BaseMul(k)
		if x.Cmp(p.X) != 0 || y.Cmp(p.Y) != 0 {
			t.Errorf("not match %v", k)
			t.Logf("%x,%x", x.Bytes(), y.Bytes())
			t.Logf("%x,%x", p.X.Bytes(), p.Y.Bytes())
			return
		}
		//t.Logf("%v", k)
	}
}

func TestErrorNewEC(t *testing.T) {
	p := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	a := "0000000000000000000000000000000000000000000000000000000000000000"
	b := "0000000000000000000000000000000000000000000000000000000000000007"
	g := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	n := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	// N is NG
	n = ""
	e := ec.NewEC(p, a, b, g, n)
	if e != nil {
		t.Errorf("invalid n")
		return
	}
	// G is NG
	g = "0579BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	e = ec.NewEC(p, a, b, g, n)
	if e != nil {
		t.Errorf("invalid n")
		return
	}
}
