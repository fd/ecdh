package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fd/secp160r1"
)

func Test_ComputeShared_P256(t *testing.T) {
	curve := elliptic.P256()

	for i := 100; i > 0; i-- {
		prv1, x1, y1, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if prv1 == nil {
			t.Fatal("expected prv1 to be non-nil")
		}
		if x1 == nil {
			t.Fatal("expected x1 to be non-nil")
		}
		if y1 == nil {
			t.Fatal("expected y1 to be non-nil")
		}

		prv2, x2, y2, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if prv2 == nil {
			t.Fatal("expected prv2 to be non-nil")
		}
		if x2 == nil {
			t.Fatal("expected x2 to be non-nil")
		}
		if y2 == nil {
			t.Fatal("expected y2 to be non-nil")
		}

		shared1 := ComputeShared(curve, x2, y2, prv1)
		shared2 := ComputeShared(curve, x1, y1, prv2)

		if !bytes.Equal(shared1, shared2) {
			t.Fatal("expected shared1 and shared2 to be equal")
		}
	}
}

func Test_ComputeShared_P160(t *testing.T) {
	curve := secp160r1.P160()

	for i := 100; i > 0; i-- {
		prv1, x1, y1, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if prv1 == nil {
			t.Fatal("expected prv1 to be non-nil")
		}
		if x1 == nil {
			t.Fatal("expected x1 to be non-nil")
		}
		if y1 == nil {
			t.Fatal("expected y1 to be non-nil")
		}

		prv2, x2, y2, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if prv2 == nil {
			t.Fatal("expected prv2 to be non-nil")
		}
		if x2 == nil {
			t.Fatal("expected x2 to be non-nil")
		}
		if y2 == nil {
			t.Fatal("expected y2 to be non-nil")
		}

		shared1 := ComputeShared(curve, x2, y2, prv1)
		shared2 := ComputeShared(curve, x1, y1, prv2)

		if !bytes.Equal(shared1, shared2) {
			t.Fatal("expected shared1 and shared2 to be equal")
		}
	}
}
