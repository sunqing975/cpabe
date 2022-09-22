package bn256

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP6 implements the field of size p⁶ as a cubic extension of gfP2 where τ³=ξ
// and ξ=i+3.
type gfP6 struct {
	X, Y, Z gfP2 // value is xτ² + yτ + Z
}

func (e *gfP6) String() string {
	return "(" + e.X.String() + ", " + e.Y.String() + ", " + e.Z.String() + ")"
}

func (e *gfP6) Set(a *gfP6) *gfP6 {
	e.X.Set(&a.X)
	e.Y.Set(&a.Y)
	e.Z.Set(&a.Z)
	return e
}

func (e *gfP6) SetZero() *gfP6 {
	e.X.SetZero()
	e.Y.SetZero()
	e.Z.SetZero()
	return e
}

func (e *gfP6) SetOne() *gfP6 {
	e.X.SetZero()
	e.Y.SetZero()
	e.Z.SetOne()
	return e
}

func (e *gfP6) IsZero() bool {
	return e.X.IsZero() && e.Y.IsZero() && e.Z.IsZero()
}

func (e *gfP6) IsOne() bool {
	return e.X.IsZero() && e.Y.IsZero() && e.Z.IsOne()
}

func (e *gfP6) Neg(a *gfP6) *gfP6 {
	e.X.Neg(&a.X)
	e.Y.Neg(&a.Y)
	e.Z.Neg(&a.Z)
	return e
}

func (e *gfP6) Frobenius(a *gfP6) *gfP6 {
	e.X.Conjugate(&a.X)
	e.Y.Conjugate(&a.Y)
	e.Z.Conjugate(&a.Z)

	e.X.Mul(&e.X, xiTo2PMinus2Over3)
	e.Y.Mul(&e.Y, xiToPMinus1Over3)
	return e
}

// FrobeniusP2 computes (xτ²+yτ+Z)^(p²) = xτ^(2p²) + yτ^(p²) + Z
func (e *gfP6) FrobeniusP2(a *gfP6) *gfP6 {
	// τ^(2p²) = τ²τ^(2p²-2) = τ²ξ^((2p²-2)/3)
	e.X.MulScalar(&a.X, xiTo2PSquaredMinus2Over3)
	// τ^(p²) = ττ^(p²-1) = τξ^((p²-1)/3)
	e.Y.MulScalar(&a.Y, xiToPSquaredMinus1Over3)
	e.Z.Set(&a.Z)
	return e
}

func (e *gfP6) FrobeniusP4(a *gfP6) *gfP6 {
	e.X.MulScalar(&a.X, xiToPSquaredMinus1Over3)
	e.Y.MulScalar(&a.Y, xiTo2PSquaredMinus2Over3)
	e.Z.Set(&a.Z)
	return e
}

func (e *gfP6) Add(a, b *gfP6) *gfP6 {
	e.X.Add(&a.X, &b.X)
	e.Y.Add(&a.Y, &b.Y)
	e.Z.Add(&a.Z, &b.Z)
	return e
}

func (e *gfP6) Sub(a, b *gfP6) *gfP6 {
	e.X.Sub(&a.X, &b.X)
	e.Y.Sub(&a.Y, &b.Y)
	e.Z.Sub(&a.Z, &b.Z)
	return e
}

func (e *gfP6) Mul(a, b *gfP6) *gfP6 {
	// "Multiplication and Squaring on Pairing-Friendly Fields"
	// Section 4, Karatsuba method.
	// http://eprint.iacr.org/2006/471.pdf
	v0 := (&gfP2{}).Mul(&a.Z, &b.Z)
	v1 := (&gfP2{}).Mul(&a.Y, &b.Y)
	v2 := (&gfP2{}).Mul(&a.X, &b.X)

	t0 := (&gfP2{}).Add(&a.X, &a.Y)
	t1 := (&gfP2{}).Add(&b.X, &b.Y)
	tz := (&gfP2{}).Mul(t0, t1)
	tz.Sub(tz, v1).Sub(tz, v2).MulXi(tz).Add(tz, v0)

	t0.Add(&a.Y, &a.Z)
	t1.Add(&b.Y, &b.Z)
	ty := (&gfP2{}).Mul(t0, t1)
	t0.MulXi(v2)
	ty.Sub(ty, v0).Sub(ty, v1).Add(ty, t0)

	t0.Add(&a.X, &a.Z)
	t1.Add(&b.X, &b.Z)
	tx := (&gfP2{}).Mul(t0, t1)
	tx.Sub(tx, v0).Add(tx, v1).Sub(tx, v2)

	e.X.Set(tx)
	e.Y.Set(ty)
	e.Z.Set(tz)
	return e
}

func (e *gfP6) MulScalar(a *gfP6, b *gfP2) *gfP6 {
	e.X.Mul(&a.X, b)
	e.Y.Mul(&a.Y, b)
	e.Z.Mul(&a.Z, b)
	return e
}

func (e *gfP6) MulGFP(a *gfP6, b *gfP) *gfP6 {
	e.X.MulScalar(&a.X, b)
	e.Y.MulScalar(&a.Y, b)
	e.Z.MulScalar(&a.Z, b)
	return e
}

// MulTau computes τ·(aτ²+bτ+c) = bτ²+cτ+aξ
func (e *gfP6) MulTau(a *gfP6) *gfP6 {
	tz := (&gfP2{}).MulXi(&a.X)
	ty := (&gfP2{}).Set(&a.Y)

	e.Y.Set(&a.Z)
	e.X.Set(ty)
	e.Z.Set(tz)
	return e
}

func (e *gfP6) Square(a *gfP6) *gfP6 {
	v0 := (&gfP2{}).Square(&a.Z)
	v1 := (&gfP2{}).Square(&a.Y)
	v2 := (&gfP2{}).Square(&a.X)

	c0 := (&gfP2{}).Add(&a.X, &a.Y)
	c0.Square(c0).Sub(c0, v1).Sub(c0, v2).MulXi(c0).Add(c0, v0)

	c1 := (&gfP2{}).Add(&a.Y, &a.Z)
	c1.Square(c1).Sub(c1, v0).Sub(c1, v1)
	xiV2 := (&gfP2{}).MulXi(v2)
	c1.Add(c1, xiV2)

	c2 := (&gfP2{}).Add(&a.X, &a.Z)
	c2.Square(c2).Sub(c2, v0).Add(c2, v1).Sub(c2, v2)

	e.X.Set(c2)
	e.Y.Set(c1)
	e.Z.Set(c0)
	return e
}

func (e *gfP6) Invert(a *gfP6) *gfP6 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf

	// Here we can give a short explanation of how it works: let j be a cubic root of
	// unity in GF(p²) so that 1+j+j²=0.
	// Then (xτ² + yτ + Z)(xj²τ² + yjτ + Z)(xjτ² + yj²τ + Z)
	// = (xτ² + yτ + Z)(Cτ²+Bτ+A)
	// = (X³ξ²+Y³ξ+Z³-3ξxyz) = F is an element of the base field (the norm).
	//
	// On the other hand (xj²τ² + yjτ + Z)(xjτ² + yj²τ + Z)
	// = τ²(Y²-ξxz) + τ(ξx²-yz) + (Z²-ξxy)
	//
	// So that's why A = (Z²-ξxy), B = (ξx²-yz), C = (Y²-ξxz)
	t1 := (&gfP2{}).Mul(&a.X, &a.Y)
	t1.MulXi(t1)

	A := (&gfP2{}).Square(&a.Z)
	A.Sub(A, t1)

	B := (&gfP2{}).Square(&a.X)
	B.MulXi(B)
	t1.Mul(&a.Y, &a.Z)
	B.Sub(B, t1)

	C := (&gfP2{}).Square(&a.Y)
	t1.Mul(&a.X, &a.Z)
	C.Sub(C, t1)

	F := (&gfP2{}).Mul(C, &a.Y)
	F.MulXi(F)
	t1.Mul(A, &a.Z)
	F.Add(F, t1)
	t1.Mul(B, &a.X).MulXi(t1)
	F.Add(F, t1)

	F.Invert(F)

	e.X.Mul(C, F)
	e.Y.Mul(B, F)
	e.Z.Mul(A, F)
	return e
}
