package bn256

import (
	"math/big"
	"errors"
)

// twistPoint implements the elliptic curve Y²=X³+3/ξ over GF(p²). Points are
// kept in Jacobian form and T=Z² when valid. The group G₂ is the set of
// n-torsion points of this curve over GF(p²) (where n = Order)
type twistPoint struct {
	X, Y, Z, T gfP2
}

var twistB = &gfP2{
	gfP{0x75046774386b8d71, 0x5bd0854a46d36cf8, 0x664327a1d41c8414, 0x96c9abb932eeb2f},
	gfP{0xb94f760fb4c5ee14, 0xdae9f8f24c3b6eb4, 0x77a675d2e52f4fe4, 0x736f31b09116c66b},
}

// twistGen is the generator of group G₂.
var twistGen = &twistPoint{
	gfP2{
		gfP{0x402c4ab7139e1404, 0xce1c368a183d85a4, 0xd67cf9a6cb8d3983, 0x3cf246bbc2a9fbe8},
		gfP{0x88f9f11da7cdc184, 0x18293f95d69509d3, 0xb5ce0c55a735d5a1, 0x15134189bfd45a0},
	},
	gfP2{
		gfP{0xbfac7d731e9e87a2, 0xa50bb8007962e441, 0xafe910a4e8270556, 0x5075c5429d69159a},
		gfP{0xc2e07c1463ea9e56, 0xee4442052072ebd2, 0x561a519486036937, 0x5bd9394cc0d2cce},
	},
	gfP2{*newGFp(0), *newGFp(1)},
	gfP2{*newGFp(0), *newGFp(1)},
}

func (c *twistPoint) String() string {
	c.MakeAffine()
	x, y := gfP2Decode(&c.X), gfP2Decode(&c.Y)
	return "(" + x.String() + ", " + y.String() + ")"
}

func (c *twistPoint) Set(a *twistPoint) {
	c.X.Set(&a.X)
	c.Y.Set(&a.Y)
	c.Z.Set(&a.Z)
	c.T.Set(&a.T)
}

// IsOnCurve returns true iff c is on the curve.
func (c *twistPoint) IsOnCurve() bool {
	c.MakeAffine()
	if c.IsInfinity() {
		return true
	}

	y2, x3 := &gfP2{}, &gfP2{}
	y2.Square(&c.Y)
	x3.Square(&c.X).Mul(x3, &c.X).Add(x3, twistB)

	return *y2 == *x3
}

func (c *twistPoint) SetInfinity() {
	c.X.SetZero()
	c.Y.SetOne()
	c.Z.SetZero()
	c.T.SetZero()
}

func (c *twistPoint) IsInfinity() bool {
	return c.Z.IsZero()
}

func (c *twistPoint) Add(a, b *twistPoint) {
	// For additional comments, see the same function in curve.go.

	if a.IsInfinity() {
		c.Set(b)
		return
	}
	if b.IsInfinity() {
		c.Set(a)
		return
	}

	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
	z12 := (&gfP2{}).Square(&a.Z)
	z22 := (&gfP2{}).Square(&b.Z)
	u1 := (&gfP2{}).Mul(&a.X, z22)
	u2 := (&gfP2{}).Mul(&b.X, z12)

	t := (&gfP2{}).Mul(&b.Z, z22)
	s1 := (&gfP2{}).Mul(&a.Y, t)

	t.Mul(&a.Z, z12)
	s2 := (&gfP2{}).Mul(&b.Y, t)

	h := (&gfP2{}).Sub(u2, u1)
	xEqual := h.IsZero()

	t.Add(h, h)
	i := (&gfP2{}).Square(t)
	j := (&gfP2{}).Mul(h, i)

	t.Sub(s2, s1)
	yEqual := t.IsZero()
	if xEqual && yEqual {
		c.Double(a)
		return
	}
	r := (&gfP2{}).Add(t, t)

	v := (&gfP2{}).Mul(u1, i)

	t4 := (&gfP2{}).Square(r)
	t.Add(v, v)
	t6 := (&gfP2{}).Sub(t4, j)
	c.X.Sub(t6, t)

	t.Sub(v, &c.X) // t7
	t4.Mul(s1, j)  // t8
	t6.Add(t4, t4) // t9
	t4.Mul(r, t)   // t10
	c.Y.Sub(t4, t6)

	t.Add(&a.Z, &b.Z) // t11
	t4.Square(t)      // t12
	t.Sub(t4, z12)    // t13
	t4.Sub(t, z22)    // t14
	c.Z.Mul(t4, h)
}

func (c *twistPoint) Double(a *twistPoint) {
	// See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
	A := (&gfP2{}).Square(&a.X)
	B := (&gfP2{}).Square(&a.Y)
	C := (&gfP2{}).Square(B)

	t := (&gfP2{}).Add(&a.X, B)
	t2 := (&gfP2{}).Square(t)
	t.Sub(t2, A)
	t2.Sub(t, C)
	d := (&gfP2{}).Add(t2, t2)
	t.Add(A, A)
	e := (&gfP2{}).Add(t, A)
	f := (&gfP2{}).Square(e)

	t.Add(d, d)
	c.X.Sub(f, t)

	t.Add(C, C)
	t2.Add(t, t)
	t.Add(t2, t2)
	c.Y.Sub(d, &c.X)
	t2.Mul(e, &c.Y)
	c.Y.Sub(t2, t)

	t.Mul(&a.Y, &a.Z)
	c.Z.Add(t, t)
}

func (c *twistPoint) Mul(a *twistPoint, scalar *big.Int) {
	sum, t := &twistPoint{}, &twistPoint{}

	for i := scalar.BitLen(); i >= 0; i-- {
		t.Double(sum)
		if scalar.Bit(i) != 0 {
			sum.Add(t, a)
		} else {
			sum.Set(t)
		}
	}

	c.Set(sum)
}

func (c *twistPoint) MakeAffine() {
	if c.Z.IsOne() {
		return
	} else if c.Z.IsZero() {
		c.X.SetZero()
		c.Y.SetOne()
		c.T.SetZero()
		return
	}

	zInv := (&gfP2{}).Invert(&c.Z)
	t := (&gfP2{}).Mul(&c.Y, zInv)
	zInv2 := (&gfP2{}).Square(zInv)
	c.Y.Mul(t, zInv2)
	t.Mul(&c.X, zInv2)
	c.X.Set(t)
	c.Z.SetOne()
	c.T.SetOne()
}

func (c *twistPoint) Neg(a *twistPoint) {
	c.X.Set(&a.X)
	c.Y.Neg(&a.Y)
	c.Z.Set(&a.Z)
	c.T.SetZero()
}

func (c *twistPoint) Frobenius(a *twistPoint) (*twistPoint, error) {
	// We have to convert a from the sextic twist
	// to the full GF(p^12) group, apply the Frobenius there, and convert
	// back.

	// The twist isomorphism is (X', Y') -> (xω², yω³). If we consider just
	// X for a moment, then after applying the Frobenius, we have x̄ω^(2p)
	// where x̄ is the conjugate of X. If we are going to apply the inverse
	// isomorphism we need a value with a single coefficient of ω² so we
	// rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
	// p, 2p-2 is a multiple of six. Therefore we can rewrite as
	// x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the
	// ω².
	// A similar argument can be made for the Y value.
	if !a.Z.IsOne() {
		return nil, errors.New("a needs to be in affine coordinates")
	}
	c.X.Conjugate(&(a.X))
	c.X.Mul(&(c.X), xiToPMinus1Over3)
	c.Y.Conjugate(&(a.Y))
	c.Y.Mul(&(c.Y), xiToPMinus1Over2)
	c.Z.SetOne()
	c.T.SetOne()

	return c, nil
}
