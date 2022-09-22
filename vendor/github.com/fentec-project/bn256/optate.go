package bn256

func lineFunctionAdd(r, p *twistPoint, q *curvePoint, r2 *gfP2) (a, b, c *gfP2, rOut *twistPoint) {
	// See the mixed addition algorithm from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	B := (&gfP2{}).Mul(&p.X, &r.T)

	D := (&gfP2{}).Add(&p.Y, &r.Z)
	D.Square(D).Sub(D, r2).Sub(D, &r.T).Mul(D, &r.T)

	H := (&gfP2{}).Sub(B, &r.X)
	I := (&gfP2{}).Square(H)

	E := (&gfP2{}).Add(I, I)
	E.Add(E, E)

	J := (&gfP2{}).Mul(H, E)

	L1 := (&gfP2{}).Sub(D, &r.Y)
	L1.Sub(L1, &r.Y)

	V := (&gfP2{}).Mul(&r.X, E)

	rOut = &twistPoint{}
	rOut.X.Square(L1).Sub(&rOut.X, J).Sub(&rOut.X, V).Sub(&rOut.X, V)

	rOut.Z.Add(&r.Z, H).Square(&rOut.Z).Sub(&rOut.Z, &r.T).Sub(&rOut.Z, I)

	t := (&gfP2{}).Sub(V, &rOut.X)
	t.Mul(t, L1)
	t2 := (&gfP2{}).Mul(&r.Y, J)
	t2.Add(t2, t2)
	rOut.Y.Sub(t, t2)

	rOut.T.Square(&rOut.Z)

	t.Add(&p.Y, &rOut.Z).Square(t).Sub(t, r2).Sub(t, &rOut.T)

	t2.Mul(L1, &p.X)
	t2.Add(t2, t2)
	a = (&gfP2{}).Sub(t2, t)

	c = (&gfP2{}).MulScalar(&rOut.Z, &q.Y)
	c.Add(c, c)

	b = (&gfP2{}).Neg(L1)
	b.MulScalar(b, &q.X).Add(b, b)

	return
}

func lineFunctionDouble(r *twistPoint, q *curvePoint) (a, b, c *gfP2, rOut *twistPoint) {
	// See the doubling algorithm for a=0 from "Faster Computation of the
	// Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
	A := (&gfP2{}).Square(&r.X)
	B := (&gfP2{}).Square(&r.Y)
	C := (&gfP2{}).Square(B)

	D := (&gfP2{}).Add(&r.X, B)
	D.Square(D).Sub(D, A).Sub(D, C).Add(D, D)

	E := (&gfP2{}).Add(A, A)
	E.Add(E, A)

	G := (&gfP2{}).Square(E)

	rOut = &twistPoint{}
	rOut.X.Sub(G, D).Sub(&rOut.X, D)

	rOut.Z.Add(&r.Y, &r.Z).Square(&rOut.Z).Sub(&rOut.Z, B).Sub(&rOut.Z, &r.T)

	rOut.Y.Sub(D, &rOut.X).Mul(&rOut.Y, E)
	t := (&gfP2{}).Add(C, C)
	t.Add(t, t).Add(t, t)
	rOut.Y.Sub(&rOut.Y, t)

	rOut.T.Square(&rOut.Z)

	t.Mul(E, &r.T).Add(t, t)
	b = (&gfP2{}).Neg(t)
	b.MulScalar(b, &q.X)

	a = (&gfP2{}).Add(&r.X, E)
	a.Square(a).Sub(a, A).Sub(a, G)
	t.Add(B, B).Add(t, t)
	a.Sub(a, t)

	c = (&gfP2{}).Mul(&rOut.Z, &r.T)
	c.Add(c, c).MulScalar(c, &q.Y)

	return
}

func mulLine(ret *gfP12, a, b, c *gfP2) {
	a2 := &gfP6{}
	a2.Y.Set(a)
	a2.Z.Set(b)
	a2.Mul(a2, &ret.X)
	t3 := (&gfP6{}).MulScalar(&ret.Y, c)

	t := (&gfP2{}).Add(b, c)
	t2 := &gfP6{}
	t2.Y.Set(a)
	t2.Z.Set(t)
	ret.X.Add(&ret.X, &ret.Y)

	ret.Y.Set(t3)

	ret.X.Mul(&ret.X, t2).Sub(&ret.X, a2).Sub(&ret.X, &ret.Y)
	a2.MulTau(a2)
	ret.Y.Add(&ret.Y, a2)
}

// sixuPlus2NAF is 6u+2 in non-adjacent form.
var sixuPlus2NAF = []int8{0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 1}

// miller implements the Miller loop for calculating the Optimal Ate pairing.
// See algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
func miller(q *twistPoint, p *curvePoint) *gfP12 {
	ret := (&gfP12{}).SetOne()

	aAffine := &twistPoint{}
	aAffine.Set(q)
	aAffine.MakeAffine()

	bAffine := &curvePoint{}
	bAffine.Set(p)
	bAffine.MakeAffine()

	minusA := &twistPoint{}
	minusA.Neg(aAffine)

	r := &twistPoint{}
	r.Set(aAffine)

	r2 := (&gfP2{}).Square(&aAffine.Y)

	for i := len(sixuPlus2NAF) - 1; i > 0; i-- {
		a, b, c, newR := lineFunctionDouble(r, bAffine)
		if i != len(sixuPlus2NAF)-1 {
			ret.Square(ret)
		}

		mulLine(ret, a, b, c)
		r = newR

		switch sixuPlus2NAF[i-1] {
		case 1:
			a, b, c, newR = lineFunctionAdd(r, aAffine, bAffine, r2)
		case -1:
			a, b, c, newR = lineFunctionAdd(r, minusA, bAffine, r2)
		default:
			continue
		}

		mulLine(ret, a, b, c)
		r = newR
	}

	// In order to calculate Q1 we have to convert q from the sextic twist
	// to the full GF(p^12) group, apply the Frobenius there, and convert
	// back.
	//
	// The twist isomorphism is (X', Y') -> (xω², yω³). If we consider just
	// X for a moment, then after applying the Frobenius, we have x̄ω^(2p)
	// where x̄ is the conjugate of X. If we are going to apply the inverse
	// isomorphism we need a value with a single coefficient of ω² so we
	// rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
	// p, 2p-2 is a multiple of six. Therefore we can rewrite as
	// x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the
	// ω².
	//
	// A similar argument can be made for the Y value.

	q1 := &twistPoint{}
	q1.X.Conjugate(&aAffine.X).Mul(&q1.X, xiToPMinus1Over3)
	q1.Y.Conjugate(&aAffine.Y).Mul(&q1.Y, xiToPMinus1Over2)
	q1.Z.SetOne()
	q1.T.SetOne()

	// For Q2 we are applying the p² Frobenius. The two conjugations cancel
	// out and we are left only with the factors from the isomorphism. In
	// the case of X, we end up with a pure number which is why
	// xiToPSquaredMinus1Over3 is ∈ GF(p). With Y we get a factor of -1. We
	// ignore this to end up with -Q2.

	minusQ2 := &twistPoint{}
	minusQ2.X.MulScalar(&aAffine.X, xiToPSquaredMinus1Over3)
	minusQ2.Y.Set(&aAffine.Y)
	minusQ2.Z.SetOne()
	minusQ2.T.SetOne()

	r2.Square(&q1.Y)
	a, b, c, newR := lineFunctionAdd(r, q1, bAffine, r2)
	mulLine(ret, a, b, c)
	r = newR

	r2.Square(&minusQ2.Y)
	a, b, c, newR = lineFunctionAdd(r, minusQ2, bAffine, r2)
	mulLine(ret, a, b, c)
	r = newR

	return ret
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT (steps 13-15 of algorithm 1 from
// http://cryptojedi.org/papers/dclxvi-20100714.pdf)
func finalExponentiation(in *gfP12) *gfP12 {
	t1 := &gfP12{}

	// This is the p^6-Frobenius
	t1.X.Neg(&in.X)
	t1.Y.Set(&in.Y)

	inv := &gfP12{}
	inv.Invert(in)
	t1.Mul(t1, inv)

	t2 := (&gfP12{}).FrobeniusP2(t1)
	t1.Mul(t1, t2)

	fp := (&gfP12{}).Frobenius(t1)
	fp2 := (&gfP12{}).FrobeniusP2(t1)
	fp3 := (&gfP12{}).Frobenius(fp2)

	fu := (&gfP12{}).Exp(t1, u)
	fu2 := (&gfP12{}).Exp(fu, u)
	fu3 := (&gfP12{}).Exp(fu2, u)

	y3 := (&gfP12{}).Frobenius(fu)
	fu2p := (&gfP12{}).Frobenius(fu2)
	fu3p := (&gfP12{}).Frobenius(fu3)
	y2 := (&gfP12{}).FrobeniusP2(fu2)

	y0 := &gfP12{}
	y0.Mul(fp, fp2).Mul(y0, fp3)

	y1 := (&gfP12{}).Conjugate(t1)
	y5 := (&gfP12{}).Conjugate(fu2)
	y3.Conjugate(y3)
	y4 := (&gfP12{}).Mul(fu, fu2p)
	y4.Conjugate(y4)

	y6 := (&gfP12{}).Mul(fu3, fu3p)
	y6.Conjugate(y6)

	t0 := (&gfP12{}).Square(y6)
	t0.Mul(t0, y4).Mul(t0, y5)
	t1.Mul(y3, y5).Mul(t1, t0)
	t0.Mul(t0, y2)
	t1.Square(t1).Mul(t1, t0).Square(t1)
	t0.Mul(t1, y1)
	t1.Mul(t1, y0)
	t0.Square(t0).Mul(t0, t1)

	return t0
}

func optimalAte(a *twistPoint, b *curvePoint) *gfP12 {
	e := miller(a, b)
	ret := finalExponentiation(e)

	if a.IsInfinity() || b.IsInfinity() {
		ret.SetOne()
	}
	return ret
}
