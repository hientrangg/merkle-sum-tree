package merkletree

import (
	"fmt"
	"math/rand"
	"log"
	"bytes"
	"os"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

)

func test_tree() {
	fmt.Println("test merkle")
	tree := New(bn254.NewMiMC() )
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

func test_tree_reader() {
	fmt.Println("test reader")
	var buf1 bytes.Buffer
	for i := 0; i < 100; i++ {
		var leaf fr.Element
		if _, err := leaf.SetRandom(); err != nil {
			log.Fatal(err)
		}
		b := leaf.Bytes()
		buf1.Write(b[:])
	}

	var buf2 bytes.Buffer
	for i := 0; i < 100; i++ {
		var leaf fr.Element
		if _, err := leaf.SetRandom(); err != nil {
			log.Fatal(err)
		}
		b := leaf.Bytes()
		buf2.Write(b[:])
	}
	// build & verify proof for an elmt in the file
	proofIndex := uint64(50)
	segmentSize := 32
	merkleRootHash, merkleRootSum, proofHash, proofSum, numLeaves, err := BuildReaderProof(&buf1, &buf2, bn254.NewMiMC(), segmentSize, proofIndex)
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}

	verified := VerifyProof(bn254.NewMiMC(), merkleRootHash, merkleRootSum, proofHash, proofSum, proofIndex, numLeaves)
	if !verified {
		log.Fatal("The merkle proof in plain go should pass")
	}
}
