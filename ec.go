package ec

import (
	"encoding/hex"
	"math/big"
)

// S256K1 is secp256k1.
// http://www.secg.org/sec2-v2.pdf
var S256K1 = NewEC(
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",   // P
	"0000000000000000000000000000000000000000000000000000000000000000",   // a
	"0000000000000000000000000000000000000000000000000000000000000007",   // b
	"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", // G
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")   // M

// S256R1 is secp256r1.
// http://www.secg.org/sec2-v2.pdf
var S256R1 = NewEC(
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",   // P
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",   // a
	"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",   // b
	"036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", // G
	"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")   // N

// EC is elliptic curve.
type EC struct {
	P *big.Int
	a *big.Int
	b *big.Int
	G *Point
	N *big.Int
}

// NewEC returns *EC.
func NewEC(p, a, b, g, n string) *EC {
	var ok bool
	ec := &EC{}
	ec.P, ok = new(big.Int).SetString(p, 16)
	if !ok {
		return nil
	}
	ec.a, ok = new(big.Int).SetString(a, 16)
	if !ok {
		return nil
	}
	ec.b, ok = new(big.Int).SetString(b, 16)
	if !ok {
		return nil
	}
	bs, err := hex.DecodeString(g)
	if err != nil {
		return nil
	}
	ec.G = ec.Parse(bs)
	if ec.G == nil {
		return nil
	}
	if ec.Infinite(ec.G) {
		return nil
	}
	ec.N, ok = new(big.Int).SetString(n, 16)
	if !ok {
		return nil
	}
	return ec
}

// Parse parses bytes to Point.
func (ec *EC) Parse(bs []byte) *Point {
	size := len(ec.P.Bytes())
	if ((bs[0] != 0x02 && bs[0] != 0x03) || len(bs) != size+1) && (bs[0] != 0x04 || len(bs) != size*2+1) {
		return nil
	}
	x := new(big.Int).SetBytes(bs[1 : size+1])
	var y *big.Int
	if len(bs) == size+1 {
		y2 := new(big.Int).Mod(
			new(big.Int).Add(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), ec.P), new(big.Int).Mul(ec.a, x)), ec.b),
			ec.P)
		y = new(big.Int).ModSqrt(y2, ec.P)
		if y == nil {
			return nil
		}
		if (bs[0] == 0x02 && y.Bit(0) == 1) || (bs[0] == 0x03 && y.Bit(0) == 0) {
			y = new(big.Int).Mod(new(big.Int).Sub(ec.P, y), ec.P)
		}
	} else {
		y = new(big.Int).SetBytes(bs[size+1:])
	}
	return &Point{x, y}
}

// Point returns a coordinate.
type Point struct {
	X *big.Int
	Y *big.Int
}

// Add is the add of points.
func (ec *EC) Add(p, q *Point) *Point {
	if ec.Infinite(p) {
		return &Point{new(big.Int).SetBytes(q.X.Bytes()), new(big.Int).SetBytes(q.Y.Bytes())}
	}
	if ec.Infinite(q) {
		return &Point{new(big.Int).SetBytes(p.X.Bytes()), new(big.Int).SetBytes(p.Y.Bytes())}
	}
	if p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) != 0 {
		return &Point{}
	}
	var s *big.Int
	// https://ja.wikipedia.org/wiki/%E6%A5%95%E5%86%86%E6%9B%B2%E7%B7%9A#%E7%BE%A4%E6%A7%8B%E9%80%A0
	if p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0 {
		// s = ( 3*Xp*Xp + a ) * ( 2*Yp ) ^ ( P - 2 ) mod P
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Add(new(big.Int).Mul(new(big.Int).Mul(big.NewInt(3), p.X), p.X), ec.a),
				new(big.Int).Exp(
					new(big.Int).Mul(big.NewInt(2), p.Y),
					new(big.Int).Sub(ec.P, big.NewInt(2)),
					ec.P)),
			ec.P)
	} else {
		// s = ( Yp - Yq ) * ( Xp - Xq ) ^ ( P - 2 ) mod P
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Sub(p.Y, q.Y),
				new(big.Int).Exp(
					new(big.Int).Sub(p.X, q.X),
					new(big.Int).Sub(ec.P, big.NewInt(2)),
					ec.P)),
			ec.P)
	}
	r := &Point{}
	// Xr = s*s - Xp - Xq mod P
	r.X = new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(s, s), new(big.Int).Add(p.X, q.X)), ec.P)
	// Yr = s*( Xp - Xr ) - Yp mod P
	r.Y = new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(s, new(big.Int).Sub(p.X, r.X)), p.Y), ec.P)
	return r
}

// Mul is the multiple of points.
func (ec *EC) Mul(x *big.Int, p *Point) *Point {
	r := &Point{}
	for i := 0; i < x.BitLen(); i++ {
		if x.Bit(i) == 1 {
			r = ec.Add(r, p)
		}
		p = ec.Add(p, p)
	}
	return r
}

// BaseMul is the multiple of base point.
func (ec *EC) BaseMul(x *big.Int) *Point {
	return ec.Mul(x, ec.G)
}

// On returns whether the point is on the elliptic curve.
func (ec *EC) On(p *Point) bool {
	if ec.Infinite(p) {
		return false
	}
	// y^2
	y2 := new(big.Int).Exp(p.Y, big.NewInt(2), ec.P)
	// x^3 + ax + b
	x3axb := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Add(
		new(big.Int).Exp(p.X, big.NewInt(3), ec.P), new(big.Int).Mul(ec.a, p.X)), ec.b), ec.P)
	// y^2 =? x^3 + ax + b
	return y2.Cmp(x3axb) == 0
}

// Infinite returns whether point is zero.
func (ec *EC) Infinite(p *Point) bool {
	if p.X == nil || p.Y == nil {
		return true
	}
	return false
}
