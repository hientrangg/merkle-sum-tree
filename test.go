package merkletree

import (
	"fmt"
	"math/rand"
	"log"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func main() {
	fmt.Println("test merkle")
	tree := New(bn254.NewMiMC())
	tree.SetIndex(3)
	s := []string{"fdhgdhgf", "fhgdhfgs", "dghdg", "fdgfhgd"}
	for i := range s {
		k := rand.Intn(60)
		tree.Push([]byte(s[i]), uint64(k))
	}
	merkleRootHash, merkleRootSum, proofHashSet, proofSumSet, proofIndex, numleaves := tree.Prove()
	fmt.Println(merkleRootSum)
	verified := VerifyProof(bn254.NewMiMC(), merkleRootHash, merkleRootSum, proofHashSet, proofSumSet, proofIndex, numleaves)
	if !verified {
		log.Fatal("The merkle proof in plain go should pass")
	}
}

