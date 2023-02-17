// Original Copyright (c) 2015 Nebulous
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package merkletree

import (
	"errors"
	"hash"
	"io"
	"encoding/binary"
)

// ReadAll will read segments of size 'segmentSize' and push them into the tree
// until EOF is reached. Success will return 'err == nil', not 'err == EOF'. No
// padding is added to the data, so the last element may be smaller than
// 'segmentSize'.
func (t *Tree) ReadAll(r1 io.Reader, r2 io.Reader, segmentSize int) error {
	for {
		//------------hash---------------
		segmentHash := make([]byte, segmentSize)
		n1, readErr := io.ReadFull(r1, segmentHash)
		if readErr == io.EOF {
			// All data has been read.
			break
		} else if readErr == io.ErrUnexpectedEOF {
			// This is the last segment, and there aren't enough bytes to fill
			// the entire segment. Note that the next call will return io.EOF.
			segmentHash = segmentHash[:n1]
		} else if readErr != nil {
			return readErr
		}

		//------------sum--------------
		segmentSum := make([]byte, segmentSize)
		n2, readErr := io.ReadFull(r2, segmentSum)
		if readErr == io.EOF {
			// All data has been read.
			break
		} else if readErr == io.ErrUnexpectedEOF {
			// This is the last segment, and there aren't enough bytes to fill
			// the entire segment. Note that the next call will return io.EOF.
			segmentSum = segmentSum[:n2]
		} else if readErr != nil {
			return readErr
		}
		t.Push(segmentHash, binary.BigEndian.Uint64(segmentSum))
	}
	return nil
}

// ReaderRoot returns the Merkle root of the data read from the reader, where
// each leaf is 'segmentSize' long and 'h' is used as the hashing function. All
// leaves will be 'segmentSize' bytes except the last leaf, which will not be
// padded out if there are not enough bytes remaining in the reader.
func ReaderRoot(r1 io.Reader, r2 io.Reader, h hash.Hash, segmentSize int) (rootHash []byte, rootSum uint64, err error) {
	tree := New(h)
	err = tree.ReadAll(r1, r2, segmentSize)
	if err != nil {
		return
	}
	rootHash, rootSum = tree.Root()
	return
}

// BuildReaderProof returns a proof that certain data is in the merkle tree
// created by the data in the reader. The merkle root, set of proofs, and the
// number of leaves in the Merkle tree are all returned. All leaves will we
// 'segmentSize' bytes except the last leaf, which will not be padded out if
// there are not enough bytes remaining in the reader.
func BuildReaderProof(r1 io.Reader, r2 io.Reader, h hash.Hash, segmentSize int, index uint64) (rootHash []byte, rootSum uint64, proofHashSet [][]byte, proofSumSet []uint64, numLeaves uint64, err error) {
	tree := New(h)
	err = tree.SetIndex(index)
	if err != nil {
		// This code should be unreachable - SetIndex will only return an error
		// if the tree is not empty, and yet the tree should be empty at this
		// point.
		panic(err)
	}
	err = tree.ReadAll(r1, r2, segmentSize)
	if err != nil {
		return
	}
	rootHash, rootSum, proofHashSet, proofSumSet, _, numLeaves = tree.Prove()
	if len(proofHashSet) == 0 {
		err = errors.New("index was not reached while creating proof")
		return
	}
	return
}
