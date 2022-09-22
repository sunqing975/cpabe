package bn256

import (
	"fmt"
	"math/big"
)

type gfP [4]uint64

func newGFp(x int64) (out *gfP) {
	if x >= 0 {
		out = &gfP{uint64(x)}
	} else {
		out = &gfP{uint64(-x)}
		gfpNeg(out, out)
	}

	montEncode(out, out)
	return out
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]
}

func (e *gfP) Invert(f *gfP) {
	bits := [4]uint64{0x185cac6c5e089665, 0xee5b88d120b5b59e, 0xaa6fecb86184dc21, 0x8fb501e34aa387f9}

	sum, power := &gfP{}, &gfP{}
	sum.Set(rN1)
	power.Set(f)

	for word := 0; word < 4; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				gfpMul(sum, sum, power)
			}
			gfpMul(power, power, power)
		}
	}

	gfpMul(sum, sum, r3)
	e.Set(sum)
}

func (e *gfP) Marshal(out []byte) {
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			out[8*w+b] = byte(e[3-w] >> (56 - 8*b))
		}
	}
}

func (e *gfP) Unmarshal(in []byte) {
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			e[3-w] += uint64(in[8*w+b]) << (56 - 8*b)
		}
	}
}

func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpMul(c, a, &gfP{1}) }

// ToInt returns a big.Int representation of e. An error is
// returned if conversion failed.
func (e *gfP) ToInt() (*big.Int, error) {
	in := &gfP{}
	montDecode(in, e)
	out, succ := new(big.Int).SetString(in.String(), 16)
	if succ == false {
		return nil, fmt.Errorf("failed conversion")
	}
	return out, nil
}

// SetInt sets e to a value given by a big.Int
// from range [0, p).
func (e *gfP) SetInt(in *big.Int) *gfP {
	in2 := new(big.Int).Set(in)
	for i := 0; i < 4; i++ {
		e[i] = in2.Uint64()
		in2.Rsh(in2, 64)
	}
	montEncode(e, e)
	return e
}

// Sqrt calculates a square root of an element
// in the GF(p) group.
func (e *gfP) Sqrt(g *gfP) (*gfP, error) {
	gInt, err := g.ToInt()
	if err != nil {
		return e, err
	}
	gSqrt := new(big.Int).ModSqrt(gInt, p)
	if gSqrt == nil {
		return e, fmt.Errorf("no sqare root")
	}
	e.SetInt(gSqrt)
	return e, nil
}
