package sha512lz

import (
	"crypto/sha512"
	"math/big"
	"math/bits"
)

/*
 A simple proof-of-work algorithm (a copy from Bitcoin block signing).

 Puzzle definition: a [64]byte body + n leading zeros
 Puzzle solution: sha512(body + response) should have n leading zeros
 the client can choose any response that satisfies the solution, but it can be expensive to find for high values of n.
 (16 leading zeros takes on average 100ms in an AMD Ryzen 3800X)
*/

// Solution is vanilla, no optimisations
func Solve(body [64]byte, leadingZeros int) [64]byte {
	sol := [64]byte{}
	solNumber := big.NewInt(0)
	oneBig := big.NewInt(1)
	for {
		copy(sol[:], solNumber.Bytes())
		sha := sha512.New()
		sha.Write(body[:])
		sha.Write(sol[:])
		shaSum := sha.Sum(nil)
		if hasAtLeastLeadingZeros(shaSum, leadingZeros) {
			return sol
		}
		solNumber = solNumber.Add(solNumber, oneBig)
	}
}

func Verify(body [64]byte, solution [64]byte, leadingZeros int) bool {
	sha := sha512.New()
	sha.Write(body[:])
	sha.Write(solution[:])
	shaSum := sha.Sum(nil)
	return hasAtLeastLeadingZeros(shaSum, leadingZeros)
}

func hasAtLeastLeadingZeros(bs []byte, minZeros int) bool {
	idx := 0
	pending := minZeros
	for idx < len(bs) {
		zeros := bits.LeadingZeros8(bs[idx])
		pending -= zeros
		if pending <= 0 {
			return true
		}
		if zeros != 8 {
			return false
		}
		idx++
	}
	return pending == 0
}
