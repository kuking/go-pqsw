package sha512lz

import (
	"crypto/rand"
	"testing"
)

var body [64]byte
var res [64]byte

func TestVerifyTrivial(t *testing.T) {
	if !Verify(body, res, 0) {
		t.Fatal("Any hash has zero leading 0 bits!")
	}
}

func TestVerifySolveSimple(t *testing.T) {
	for lz := 0; lz < 10; lz++ {
		var payload [64]byte
		n, err := rand.Read(payload[:])
		if err != nil {
			t.Fatalf("Could not get randomness, or the expected ammount, expected: %v, error: %v", n, err)
		}
		//start := time.Now()
		solution := Solve(payload, lz)
		//elapsed := time.Since(start)
		//fmt.Printf("It took %v to calculate solution for %v leading Zeros\n", elapsed, lz)
		if !Verify(payload, solution, lz) {
			t.Fatalf("Solution did not verify for lz: %v, sol: %v", lz, solution)
		}
	}
}

func TestPendingZeros(t *testing.T) {
	var sol []byte
	if hasAtLeastLeadingZeros(sol, 0) == false {
		t.Fatal("an empty array has 0 leading zeros!")
	}
	if hasAtLeastLeadingZeros(sol, 1) == true {
		t.Fatal("an empty array does NOT have 1 leading zero!")
	}
	sol = append(sol, 0)
	if hasAtLeastLeadingZeros(sol, 0) == false {
		t.Fatal("{0} array has more than 0 leading zeros")
	}
	if hasAtLeastLeadingZeros(sol, 8) == false {
		t.Fatal("{0} array a minimum of 8 leading zeros")
	}
	if hasAtLeastLeadingZeros(sol, 9) == true {
		t.Fatal("{0} array can not have more than 8 zeros")
	}
	sol = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if hasAtLeastLeadingZeros(sol, 16*8) == false {
		t.Fatal("16 zeros should have 16*8 zero bits")
	}
	if hasAtLeastLeadingZeros(sol, (16*8)+1) == true {
		t.Fatal("16 zeros should NOT have (16*8)+1 zero bits")
	}
	sol = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if hasAtLeastLeadingZeros(sol, 16*8) == true {
		t.Fatal("16 zeros and a '1' should NOT have 16*8 zero bits")
	}
	if hasAtLeastLeadingZeros(sol, (16*8)-1) == false {
		t.Fatal("16 zeros and a '1' should have (16*8)-1 zero bits")
	}
	if hasAtLeastLeadingZeros(sol, 5000) == true {
		t.Fatal("16 zeros can not have 5000 zero bits")
	}
}
