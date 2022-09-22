package bn256

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

import (
	"math/big"
)

// gfP12 implements the field of size P¹² as a quadratic extension of gfP6
// where ω²=τ.
type gfP12 struct {
	X, Y gfP6 // value is xω + Y
}

var gfP12Gen *gfP12 = &gfP12{
	X: gfP6{
		X: gfP2{
			X: gfP{0x62d608d6bb67a4fb, 0x9a66ec93f0c2032f, 0x5391628e924e1a34, 0x2162dbf7de801d0e},
			Y: gfP{0x3e0c1a72bf08eb4f, 0x4972ec05990a5ecc, 0xf7b9a407ead8007e, 0x3ca04c613572ce49},
		},
		Y: gfP2{
			X: gfP{0xace536a5607c910e, 0xda93774a941ddd40, 0x5de0e9853b7593ad, 0xe05bb926f513153},
			Y: gfP{0x3f4c99f8abaf1a22, 0x66d5f6121f86dc33, 0x8e0a82f68a50abba, 0x819927d1eebd0695},
		},
		Z: gfP2{
			X: gfP{0x7cdef49c5477faa, 0x40eb71ffedaa199d, 0xbc896661f17c9b8f, 0x3144462983c38c02},
			Y: gfP{0xcd09ee8dd8418013, 0xf8d050d05faa9b11, 0x589e90a555507ee1, 0x58e4ab25f9c49c15},
		},
	},
	Y: gfP6{
		X: gfP2{
			X: gfP{0x7e76809b142d020b, 0xd9949d1b2822e995, 0x3de93d974f84b076, 0x144523477028928d},
			Y: gfP{0x79952799f9ef4b0, 0x4102c47aa3df01c6, 0xfa82a633c53da2e1, 0x54c3f0392f9f7e0e},
		},
		Y: gfP2{
			X: gfP{0xd3432a335533272b, 0xa008fbbdc7d74f4a, 0x68e3c81eb7295ed9, 0x17fe34c21fdecef2},
			Y: gfP{0xfb0bc4c0ef6df55f, 0x8bdc585b70bc2120, 0x17d498d2cb720def, 0x2a368248319b899c},
		},
		Z: gfP2{
			X: gfP{0xf8487d81cb354c6c, 0x7421be69f1522caa, 0x6940c778b9fb2d54, 0x7da4b04e102bb621},
			Y: gfP{0x97b91989993e7be4, 0x8526545356eab684, 0xb050073022eb1892, 0x658b432ad09939c0},
		},
	},
}

func (e *gfP12) String() string {
	return "(" + e.X.String() + "," + e.Y.String() + ")"
}

func (e *gfP12) Set(a *gfP12) *gfP12 {
	e.X.Set(&a.X)
	e.Y.Set(&a.Y)
	return e
}

func (e *gfP12) SetZero() *gfP12 {
	e.X.SetZero()
	e.Y.SetZero()
	return e
}

func (e *gfP12) SetOne() *gfP12 {
	e.X.SetZero()
	e.Y.SetOne()
	return e
}

func (e *gfP12) IsZero() bool {
	return e.X.IsZero() && e.Y.IsZero()
}

func (e *gfP12) IsOne() bool {
	return e.X.IsZero() && e.Y.IsOne()
}

func (e *gfP12) Conjugate(a *gfP12) *gfP12 {
	e.X.Neg(&a.X)
	e.Y.Set(&a.Y)
	return e
}

func (e *gfP12) Neg(a *gfP12) *gfP12 {
	e.X.Neg(&a.X)
	e.Y.Neg(&a.Y)
	return e
}

// Frobenius computes (xω+Y)^P = X^P ω·ξ^((P-1)/6) + Y^P
func (e *gfP12) Frobenius(a *gfP12) *gfP12 {
	e.X.Frobenius(&a.X)
	e.Y.Frobenius(&a.Y)
	e.X.MulScalar(&e.X, xiToPMinus1Over6)
	return e
}

// FrobeniusP2 computes (xω+Y)^P² = X^P² ω·ξ^((P²-1)/6) + Y^P²
func (e *gfP12) FrobeniusP2(a *gfP12) *gfP12 {
	e.X.FrobeniusP2(&a.X)
	e.X.MulGFP(&e.X, xiToPSquaredMinus1Over6)
	e.Y.FrobeniusP2(&a.Y)
	return e
}

func (e *gfP12) FrobeniusP4(a *gfP12) *gfP12 {
	e.X.FrobeniusP4(&a.X)
	e.X.MulGFP(&e.X, xiToPSquaredMinus1Over3)
	e.Y.FrobeniusP4(&a.Y)
	return e
}

func (e *gfP12) Add(a, b *gfP12) *gfP12 {
	e.X.Add(&a.X, &b.X)
	e.Y.Add(&a.Y, &b.Y)
	return e
}

func (e *gfP12) Sub(a, b *gfP12) *gfP12 {
	e.X.Sub(&a.X, &b.X)
	e.Y.Sub(&a.Y, &b.Y)
	return e
}

func (e *gfP12) Mul(a, b *gfP12) *gfP12 {
	tx := (&gfP6{}).Mul(&a.X, &b.Y)
	t := (&gfP6{}).Mul(&b.X, &a.Y)
	tx.Add(tx, t)

	ty := (&gfP6{}).Mul(&a.Y, &b.Y)
	t.Mul(&a.X, &b.X).MulTau(t)

	e.X.Set(tx)
	e.Y.Add(ty, t)
	return e
}

func (e *gfP12) MulScalar(a *gfP12, b *gfP6) *gfP12 {
	e.X.Mul(&e.X, b)
	e.Y.Mul(&e.Y, b)
	return e
}

func (c *gfP12) Exp(a *gfP12, power *big.Int) *gfP12 {
	sum := (&gfP12{}).SetOne()
	t := &gfP12{}

	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum)
		if power.Bit(i) != 0 {
			sum.Mul(t, a)
		} else {
			sum.Set(t)
		}
	}

	c.Set(sum)
	return c
}

func (e *gfP12) Square(a *gfP12) *gfP12 {
	// Complex squaring algorithm
	v0 := (&gfP6{}).Mul(&a.X, &a.Y)

	t := (&gfP6{}).MulTau(&a.X)
	t.Add(&a.Y, t)
	ty := (&gfP6{}).Add(&a.X, &a.Y)
	ty.Mul(ty, t).Sub(ty, v0)
	t.MulTau(v0)
	ty.Sub(ty, t)

	e.X.Add(v0, v0)
	e.Y.Set(ty)
	return e
}

func (e *gfP12) Invert(a *gfP12) *gfP12 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2 := &gfP6{}, &gfP6{}

	t1.Square(&a.X)
	t2.Square(&a.Y)
	t1.MulTau(t1).Sub(t2, t1)
	t2.Invert(t1)

	e.X.Neg(&a.X)
	e.Y.Set(&a.Y)
	e.MulScalar(e, t2)
	return e
}
