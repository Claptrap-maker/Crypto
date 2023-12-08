/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * Copyright (C) 2014  Yawning Angel (yawning at schwanenlied dot me)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *********************************************************************************/

// Package ntru implements the NTRUEncrypt public key cryptosystem.
package ntru

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"kursach/pkg/ntru/bitpack"
	"kursach/pkg/ntru/bpgm3"
	"kursach/pkg/ntru/igf2"
	"kursach/pkg/ntru/mgf1"
	"kursach/pkg/ntru/mgftp1"
	"kursach/pkg/ntru/params"
	"kursach/pkg/ntru/polynomial"
	"log"
)

const (
	blobHeaderLen           = 4
	blobPublicKeyV1         = 1
	blobPrivateKeyDefaultV1 = 2
)

var inverterMod2048 polynomial.Inverter

// InvalidParamError is the error returned when an invalid parameter set is
// specified during key generation.
type InvalidParamError params.Oid

func (e InvalidParamError) Error() string {
	return fmt.Sprintf("ntru: unsupported OID: %d", e)
}

// ErrMessageTooLong is the error returned when a message is too long for the
// parameter set.
var ErrMessageTooLong = errors.New("ntru: message too long for chosen parameter set")

// ErrDecryption is the error returned when decryption fails.  It is
// deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("ntru: decryption error")

// ErrInvalidKey is the error returned when the key is invalid.
var ErrInvalidKey = errors.New("ntru: invalid key")

// A PublicKey represents a NTRUEncrypt public key.
type PublicKey struct {
	Params *params.KeyParams
	H      *polynomial.Full
}

// Size returns the length of the binary representation of this public key.
func (pub *PublicKey) Size() int {
	return 1 + len(pub.Params.OIDBytes) + bitpack.PackedLength(int(pub.Params.N), int(pub.Params.Q))
}

// Bytes returns the binary representation of a public key.
func (pub *PublicKey) Bytes() []byte {
	ret := make([]byte, pub.Size())
	ret[0] = blobPublicKeyV1
	copy(ret[1:4], pub.Params.OIDBytes)
	bitpack.Pack(int(pub.Params.N), int(pub.Params.Q), pub.H.P, 0, ret, blobHeaderLen)
	return ret
}

// NewPublicKey decodes a PublicKey from it's binary representation.
func NewPublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) < blobHeaderLen {
		return nil, fmt.Errorf("ntru: invalid public key blob length")
	}
	if raw[0] != blobPublicKeyV1 {
		return nil, fmt.Errorf("ntru: invalid public key blob tag")
	}
	p := params.ParamFromBytes(raw[1:4])
	if p == nil {
		return nil, fmt.Errorf("ntru: unsupported parameter set")
	}

	packedHLen := bitpack.UnpackedLength(int(p.N), int(p.Q))
	if blobHeaderLen+packedHLen != len(raw) {
		return nil, fmt.Errorf("ntru: invalid public key blob length")
	}

	h := polynomial.New(int(p.N))
	bitpack.Unpack(int(p.N), int(p.Q), raw, blobHeaderLen, h.P, 0)
	return &PublicKey{Params: p, H: h}, nil
}

// generateM calculates M = b | mLen | m | p0.
func (pub *PublicKey) generateM(msg []byte, rng io.Reader) (m []byte, err error) {
	db := pub.Params.Db >> 3
	mLen := db + pub.Params.LLen + int16(pub.Params.MaxMsgLenBytes) + 1
	m = make([]byte, mLen)
	if _, err = rng.Read(m); err != nil {
		return nil, err
	}

	m[db] = byte(len(msg))
	copy(m[db+pub.Params.LLen:], msg)
	for i := db + pub.Params.LLen + int16(len(msg)); i < mLen; i++ {
		m[i] = 0
	}
	return
}

// convPolyTrinaryToBinary converts a polynomial to a bit-packed binary
// array.
func (pub *PublicKey) convPolyTrinaryToBinary(trin *polynomial.Full) (b []byte) {
	// The output of this operation is supposed to have the form
	// (b | mLen | m | p0) so we can calculate how many bytes that is supposed
	// to be.

	numBytes := int(pub.Params.Db/8) + int(pub.Params.LLen) + pub.Params.MaxMsgLenBytes + 1
	b = make([]byte, numBytes)
	i, j := 0, 0
	for j < numBytes {
		convPolyTrinaryToBinaryBlockHelper(i, trin.P, j, b)
		i += 16
		j += 3
	}
	return
}

// formSData forms the byte sequece sData = <OID | m | b | hTrunc> where hTrunc
// is a prefix of the bit-packed representation of the public key h.
func (pub *PublicKey) formSData(m []byte, mOffset, mLen int, b []byte, bOffset int) (sData []byte) {
	bLen := int(pub.Params.Db >> 3)
	hLen := int(pub.Params.PkLen >> 3)

	offset := 0
	sData = make([]byte, len(pub.Params.OIDBytes)+mLen+bLen+hLen)
	copy(sData[offset:], pub.Params.OIDBytes)
	offset += len(pub.Params.OIDBytes)

	copy(sData[offset:], m[mOffset:mOffset+mLen])
	offset += mLen

	copy(sData[offset:], b[bOffset:bOffset+bLen])
	offset += bLen

	bitpack.PackN(int(pub.Params.N), int(pub.Params.Q), hLen, pub.H.P, 0, sData, offset)
	return
}

// calcEncryptionMask calculates the trinomial 'mask' using a bit-packed 'R mod
// 4' as the seed of the MGF_TP_1 algorithm.
func (pub *PublicKey) calcEncryptionMask(r *polynomial.Full) (p *polynomial.Full) {
	var err error
	r4 := calcPolyMod4Packed(r)
	mgf := mgf1.New(pub.Params.MGFHash, int(pub.Params.MinCallsMask), true, r4, 0, len(r4))
	defer mgf.Close()
	p, err = mgftp1.GenTrinomial(int(pub.Params.N), mgf)
	if err != nil {
		panic(err)
	}
	return
}

// A PrivateKey represents a NTRUEncrypt private key.
type PrivateKey struct {
	PublicKey
	F *polynomial.Full
}

// Size returns the length of the binary representation of this private key.
func (priv *PrivateKey) Size() int {
	commonSize := 1 + len(priv.Params.OIDBytes) + bitpack.PackedLength(int(priv.Params.N), int(priv.Params.Q))
	packedSize := priv.packedSize()
	listedSize := priv.listedSize()
	if priv.packedSize() < priv.listedSize() {
		return commonSize + packedSize
	}
	return commonSize + listedSize
}

// Bytes returns the binary representation of a private key.
func (priv *PrivateKey) Bytes() []byte {
	ret := make([]byte, priv.Size())
	ret[0] = blobPrivateKeyDefaultV1
	copy(ret[1:4], priv.Params.OIDBytes)
	fOff := blobHeaderLen
	fOff += bitpack.Pack(int(priv.Params.N), int(priv.Params.Q), priv.H.P, 0, ret, fOff)

	F := priv.recoverF()
	if priv.packedSize() < priv.listedSize() {
		// Convert f to a packed F, and write it out.
		fBuf := &bufByteRdWriter{b: ret, off: fOff}
		mgftp1.EncodeTrinomial(F, fBuf)
	} else {
		// Convert f to a listed f.
		bitpack.PackListedCoefficients(F, int(priv.Params.Df), int(priv.Params.Df), ret, fOff)
	}
	F.Obliterate()

	return ret
}

// NewPrivateKey decodes a PrivateKey from it's binary representation.
func NewPrivateKey(raw []byte) (*PrivateKey, error) {
	priv := &PrivateKey{}

	if len(raw) < blobHeaderLen {
		return nil, fmt.Errorf("ntru: invalid private key blob length")
	}
	if raw[0] != blobPrivateKeyDefaultV1 {
		return nil, fmt.Errorf("ntru: invalid private key blob tag")
	}
	p := params.ParamFromBytes(raw[1:4])
	if p == nil {
		return nil, fmt.Errorf("ntru: unsupported parameter set")
	}
	priv.Params = p

	expLen := 1 + len(priv.Params.OIDBytes) + bitpack.PackedLength(int(priv.Params.N), int(priv.Params.Q))
	packedFLen := int((p.N + 4) / 5)
	packedListedFLen := priv.listedSize()
	if packedFLen < packedListedFLen {
		expLen += packedFLen
	} else {
		expLen += packedListedFLen
	}

	if expLen != len(raw) {
		return nil, fmt.Errorf("ntru: invalid private key blob length")
	}

	// Recover h.
	fOff := blobHeaderLen
	priv.H = polynomial.New(int(p.N))
	fOff += bitpack.Unpack(int(p.N), int(p.Q), raw, blobHeaderLen, priv.H.P, 0)

	// Recover F.
	if packedFLen < packedListedFLen {
		fBuf := &bufByteRdWriter{b: raw, off: fOff}
		priv.F, _ = mgftp1.GenTrinomial(int(p.N), fBuf)
	} else {
		priv.F = polynomial.New(int(p.N))
		bitpack.UnpackListedCoefficients(priv.F, int(p.N), int(p.Df), int(p.Df), raw, fOff)
	}

	// Compute f = 1+p*F.
	for i, v := range priv.F.P {
		priv.F.P[i] = (p.P * v) & 0xfff
	}
	priv.F.P[0]++

	return priv, nil
}

// packedSize returns the size of F encoded in the packed format.
func (priv *PrivateKey) packedSize() int {
	return (len(priv.F.P) + 4) / 5
}

// listedSize returns the size of F encoded in the listed format.
func (priv *PrivateKey) listedSize() int {
	return bitpack.PackedLength(2*int(priv.Params.Df), int(priv.Params.N))
}

// Calculate F = (f - 1) / p.
func (priv *PrivateKey) recoverF() *polynomial.Full {
	F := polynomial.New(len(priv.F.P))
	F.P[0] = int16(int8(priv.F.P[0]-1) / int8(priv.Params.P))
	for i := 1; i < len(F.P); i++ {
		F.P[i] = int16(int8(priv.F.P[i]) / int8(priv.Params.P))
	}
	return F
}

// parseMsgLengthFromM pulls out the message length from a ciphertext.
func (priv *PrivateKey) parseMsgLengthFromM(m []byte) (l int) {
	db := priv.Params.Db >> 3
	if len(m) < int(db+priv.Params.LLen) {
		return -1
	}
	for i := db; i < db+priv.Params.LLen; i++ {
		l = (l << 8) | int(m[i])
	}
	return
}

// verifyMFormat validates that a ciphertext is well formed, and returns the
// message length or -1.
func (priv *PrivateKey) verifyMFormat(m []byte) int {
	ok := true
	db := priv.Params.Db >> 3

	// This is the number of bytes in the formatted message:
	numBytes := db + priv.Params.LLen + int16(priv.Params.MaxMsgLenBytes) + 1
	if len(m) != int(numBytes) {
		ok = false
	}

	// 1) First db bytes are random data.

	// 2) Next lLen bytes are the message length.  Decode and verify.
	//
	// XXX/Yawning This whole block is kind of broken in the Java code.
	//  * It treats the short buffer case as the same as a 0 length msg (ok,
	//    though confusing, since the total length check has failed and ok is
	//    false at this point).
	//  * It checks mLen >= priv.Params.MaxMsgLenBytes, which is blatantly
	//    incorrect and will cause ciphertexts containing maximum length
	//    payload to fail.
	mLen := priv.parseMsgLengthFromM(m)
	if mLen < 0 || mLen > priv.Params.MaxMsgLenBytes {
		// mLen = 1 so that later steps will work (though we will return an
		// error).
		mLen = 1
		ok = false
	}

	// 3) Next mLen bytes are m.

	// 4) Remaining bytes are p0.
	for i := int(db+priv.Params.LLen) + mLen; i < len(m); i++ {
		ok = ok && m[i] == 0
	}

	if ok {
		return mLen
	}
	return -1
}

// GenerateKey generates a NTRUEncrypt keypair with the given parameter set
// using the random src random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, oid params.Oid) (priv *PrivateKey, err error) {
	keyParams := params.Param(oid)
	if keyParams == nil {
		return nil, InvalidParamError(oid)
	}
	prng := readerToByteReader(random)
	igf := igf2.NewFromReader(keyParams.N, keyParams.C, prng)

	// Generate trinomial g that is invertible.
	var g *polynomial.Full
	for isInvertible := false; !isInvertible; {
		if g, err = bpgm3.GenTrinomial(keyParams.N, keyParams.Dg+1, keyParams.Dg, igf); err != nil {
			return nil, err
		}
		gInv := inverterMod2048.Invert(g)
		isInvertible = gInv != nil
	}

	// Create F, f=1+p*F, and F^-1 mod q.
	var F, f, fInv *polynomial.Full
	for isInvertible := false; !isInvertible; {
		if F, err = bpgm3.GenTrinomial(keyParams.N, keyParams.Df, keyParams.Df, igf); err != nil {
			return nil, err
		}
		f = polynomial.New(int(keyParams.N))
		for i := range f.P {
			f.P[i] = (keyParams.P * F.P[i]) & 0xfff
		}
		f.P[0]++

		fInv = inverterMod2048.Invert(f)
		isInvertible = fInv != nil
	}

	// Calculate h = f^-1 * g * p mod q.
	h := polynomial.Convolution(fInv, g)
	for i := range h.P {
		h.P[i] = (h.P[i] * keyParams.P) % keyParams.Q
		if h.P[i] < 0 {
			h.P[i] += keyParams.Q
		}
	}

	fInv.Obliterate()
	F.Obliterate()

	priv = &PrivateKey{}
	priv.Params = keyParams
	priv.H = h
	priv.F = f
	return
}

// Encrypt encrypts the given message with NTRUEncrypt.  The message must be no
// longer than the maximum allowed plaintext size that is depending on the
// parameter set.
func Encrypt(random io.Reader, pub *PublicKey, msg []byte) (out []byte, err error) {
	//Сначала проверяется, что публичный ключ pub имеет правильный формат и что длина
	//сообщения msg не превышает максимально допустимую длину pub.Params.MaxMsgLenBytes.
	//Если это не так, он возвращает ошибку.
	if pub.Params == nil || pub.H == nil {
		return nil, ErrInvalidKey
	}
	if pub.Params.MaxMsgLenBytes < len(msg) {
		return nil, ErrMessageTooLong
	}

	//Затем в цикле генерируется случайное число r и формируется полином Mtrin из сообщения msg
	//и дополнительных данных, таких как OID (идентификатор объекта) и длина сообщения.
	//Это делается с помощью функций pub.generateM и convPolyBinaryToTrinary.
	var mPrime, R *polynomial.Full
	for {
		var M []byte
		M, err = pub.generateM(msg, random)
		if err != nil {
			return nil, err
		}

		Mtrin := polynomial.NewFromCoeffs(convPolyBinaryToTrinary(int(pub.Params.N), M))

		//Далее формируется sData, которое является входом для функции генерации r. Это делается с помощью
		//функции pub.formSData, которая объединяет OID, msg, b (байт, содержащий длину сообщения) и
		//hTrunc (сокращенная версия pub.H, которая является частью публичного ключа).
		sData := pub.formSData(msg, 0, len(msg), M, 0)

		// Затем вызывается функция bpgm3.GenTrinomial, которая использует алгоритм BPGM3 для генерации
		//трехчленного полинома r с заданными параметрами pub.Params.N, pub.Params.Dr и pub.Params.C.
		//Эта функция также использует igf2 (инвертированный генератор функций), который основан на
		//хеш-функции pub.Params.IGFHash и принимает sData в качестве входа.
		var r *polynomial.Full
		igf := igf2.New(pub.Params.N, pub.Params.C, pub.Params.IGFHash, int(pub.Params.MinCallsR), sData, 0, len(sData))
		r, err = bpgm3.GenTrinomial(pub.Params.N, pub.Params.Dr, pub.Params.Dr, igf)
		if err != nil {
			return nil, err
		}

		// После того, как r сгенерирован, вычисляется R, который является произведением r и pub.H
		//по модулю pub.Params.Q. Это делается с помощью функции polynomial.ConvolutionModN, которая
		//реализует свертку полиномов по модулю.
		R = polynomial.ConvolutionModN(r, pub.H, int(pub.Params.Q))

		// Затем вычисляется R4, который является R по модулю 4, и преобразует его в октетную строку.
		//Он также вычисляет mask, который является результатом применения функции MGF1
		//(маскирующей генерирующей функции) к R4. Это делается с помощью функции pub.calcEncryptionMask,
		//которая использует алгоритм MGF1, основанный на хеш-функции SHA-1.
		mask := pub.calcEncryptionMask(R)

		// Затем вычисляется mPrime, который является суммой Mtrin и mask по модулю pub.Params.P.
		//Это делается с помощью функции polynomial.AddAndRecenter, которая также перецентрирует полином,
		//чтобы его коэффициенты были в диапазоне от -1 до 1.
		mPrime = Mtrin.AddAndRecenter(mask, int(pub.Params.P), -1)

		// Затем проверяется, что mPrime удовлетворяет условию dm0, то есть количество единиц,
		//нулей и минус единиц в mPrime не меньше, чем pub.Params.Dm0. Это делается с помощью
		//функции checkDm0. Если это условие не выполняется, он повторяет весь цикл с новым случайным числом r.
		if checkDm0(mPrime, pub.Params.Dm0) {
			break
		}
	}

	// Вычисляется e, который является суммой R и mPrime по модулю pub.Params.Q. Это делается с помощью
	//функции polynomial.Add. Этот полином e является зашифрованным сообщением, которое он упаковывает
	//в биты с помощью функции bitpack.Pack и возвращает в качестве результата.
	e := R.Add(mPrime, int(pub.Params.Q))
	cLen := bitpack.PackedLength(len(e.P), int(pub.Params.Q))
	out = make([]byte, cLen)
	bitpack.Pack(len(e.P), int(pub.Params.Q), e.P, 0, out, 0)
	return
}

// Decrypt принимает два аргумента: priv - указатель на структуру PrivateKey, которая содержит параметры,
// многочлены f и h, и ciphertext - байтовый массив, который представляет зашифрованное сообщение.
func Decrypt(priv *PrivateKey, ciphertext []byte) (out []byte, err error) {
	//Если priv.Params, priv.H или priv.F равны nil, функция возвращает ошибку ErrInvalidKey,
	//которая означает, что ключ недействителен или не инициализирован.
	if priv.Params == nil || priv.H == nil || priv.F == nil {
		log.Println("1")
		return nil, ErrInvalidKey
	}

	// Ожидаемая длина шифртекста в битах вычисляется с помощью функции bitpack.PackedLength, которая принимает
	//два аргумента: n - степень многочленов, и q - модуль, по которому производятся вычисления. Если длина
	//шифртекста не равна ожидаемой, функция возвращает ошибку ErrDecryption, которая означает, что шифртекст
	//поврежден или неправильный.
	expectedCTLength := bitpack.PackedLength(int(priv.Params.N), int(priv.Params.Q))
	if len(ciphertext) != expectedCTLength {
		log.Println("2")
		return nil, ErrDecryption
	}

	fail := false

	// Шифртекст распаковывается в многочлен e с помощью функции bitpack.Unpack, которая принимает шесть аргументов:
	//n - степень многочленов, q - модуль, in - входной байтовый массив, inOffset - смещение в байтах во входном
	//массиве, out - выходной массив целых чисел, outOffset - смещение в элементах в выходном массиве. Функция
	//возвращает количество распакованных байтов. Если это число не равно длине шифртекста, функция возвращает
	//ошибку ErrDecryption.
	e := polynomial.New(int(priv.Params.N))
	numUnpacked := bitpack.Unpack(int(priv.Params.N), int(priv.Params.Q), ciphertext, 0, e.P, 0)
	if numUnpacked != len(ciphertext) {
		log.Println("3")
		return nil, ErrDecryption
	}

	// Вычисляется многочлен a = f * e mod q с помощью функции polynomial.ConvolutionModN, которая принимает три
	//аргумента: f и e - многочлены, q - модуль. Коэффициенты многочлена a приводятся к диапазону [A…A+q-1],
	//где A - нижняя граница коэффициентов расшифровки (-q/2 во всех наборах параметров).
	ci := polynomial.ConvolutionModN(priv.F, e, int(priv.Params.Q))
	for i := range ci.P {
		if ci.P[i] >= priv.Params.Q/2 {
			ci.P[i] -= priv.Params.Q
		}
	}

	// Вычисляется кандидат на сообщение ci = a mod p в [-1, 0, 1], где p - малый модуль, равный 3. Для этого
	//коэффициенты многочлена a делятся по модулю p и приводятся к диапазону [-2…2]. Затем коэффициенты, равные
	//2 или -2, заменяются на -1 или 1 соответственно.
	for i := 0; i < int(priv.Params.N); i++ {
		ci.P[i] = int16(int8((ci.P[i] % priv.Params.P) & 0xff))
		switch ci.P[i] {
		case 2:
			ci.P[i] = -1
		case -2:
			ci.P[i] = 1
		}
	}

	// Подсчитывается количество единиц, нулей и минус единиц в ci. Если какое-то из этих чисел меньше,
	//чем dm0 - параметр, определяющий минимальное расстояние Хэмминга, функция устанавливает флаг fail
	//в true. Это проверка на то, что ci является действительным троичным многочленом.
	if !checkDm0(ci, priv.Params.Dm0) {
		fail = true
	}

	// Вычисляется кандидат на r*h: cR = e - ci с помощью функции polynomial.Subtract, которая принимает три
	//аргумента: e и ci - многочлены, q - модуль.
	cR := e.Subtract(ci, int(priv.Params.Q))

	// Вычисляется cR4 = cR mod 4, где 4 - малый модуль, равный 2^2.
	// Генерируется маскирующий многочлен mask с помощью функции priv.calcEncryptionMask, которая принимает один
	//аргумент: cR - многочлен. Эта функция реализует алгоритм MGF, который использует хеш-функцию SHA-256 для
	//создания псевдослучайной последовательности битов из cR4.
	mask := priv.calcEncryptionMask(cR)

	// Формируется многочлен cMtrin путем вычитания cm’ и mask по модулю p с помощью функции
	//polynomial.SubtractAndRecenter, которая принимает четыре аргумента: cm’ и mask - многочлены, p - модуль,
	//center - центр диапазона коэффициентов. Этот многочлен представляет собой зашифрованное сообщение в троичном виде.
	cMtrin := ci.SubtractAndRecenter(mask, int(priv.Params.P), -1)

	// Конвертируется cMtrin в cMbin с помощью функции priv.convPolyTrinaryToBinary, которая принимает один
	//аргумент: cMtrin - многочлен. Эта функция преобразует коэффициенты в двоичные биты с помощью
	//кодирования 0 -> 00, 1 -> 01, -1 -> 10. Отбрасываются лишние биты в конце.
	cM := priv.convPolyTrinaryToBinary(cMtrin)

	// Разбирается cMbin как b || l || m || p0, где b - блок длины db битов, l - длина сообщения в байтах,
	//m - сообщение, p0 - дополнение нулями до кратности 8 битов. Проверяется, что формат соответствует ожидаемому,
	//иначе функция устанавливает флаг fail в true. Длина сообщения mLen вычисляется с помощью функции
	//priv.verifyMFormat, которая принимает один аргумент: cM - байтовый массив.
	mOffset := int(priv.Params.Db/8 + priv.Params.LLen)
	mLen := priv.verifyMFormat(cM)
	if mLen < 0 {
		mLen = 1
		fail = true
	}

	// Формируется массив байтов sData из OID, m, b, hTrunc с помощью функции priv.formSData, которая принимает
	//четыре аргумента: cM, mOffset, mLen, b - байтовые массивы, и bOffset - смещение в байтах в массиве b.
	//OID - идентификатор объекта, который определяет набор параметров, hTrunc - усеченная версия многочлена h.
	//Этот массив используется для генерации многочлена cr.
	sData := priv.formSData(cM, mOffset, mLen, cM, 0)

	// Вычисляется многочлен cr из sData с помощью функции bpgm3.GenTrinomial, которая принимает четыре аргумента:
	//n - степень многочлена, dr - параметр, определяющий количество единиц и минус единиц в многочлене,
	//igf - генератор псевдослучайных чисел. Эта функция генерирует троичный многочлен с заданным расстоянием Хэмминга.
	//Если функция возвращает ошибку, функция устанавливает флаг fail в true.
	igf := igf2.New(priv.Params.N, priv.Params.C, priv.Params.IGFHash, int(priv.Params.MinCallsR), sData, 0, len(sData))
	cr, err := bpgm3.GenTrinomial(priv.Params.N, priv.Params.Dr, priv.Params.Dr, igf)
	if err != nil {
		fail = true
	}
	igf.Close()

	// Вычисляется многочлен cR’ = h * cr mod q с помощью функции polynomial.ConvolutionModN. Если cR не равен cR’,
	//функция устанавливает флаг fail в true. Это проверка на то, что cr является действительным многочленом,
	//соответствующим шифртексту.
	cRPrime := polynomial.ConvolutionModN(cr, priv.H, int(priv.Params.Q))
	if !cR.Equals(cRPrime) {
		fail = true
	}

	//Если флаг fail равен true, функция возвращает ошибку ErrDecryption. Иначе функция возвращает сообщение m,
	//которое является частью массива cM с позиции mOffset до позиции mOffset+mLen.
	if fail {
		log.Println("4")
		return nil, ErrDecryption
	}

	out = cM[mOffset : mOffset+mLen]
	return
}

// convPolyBinaryToTrinaryHelper converts 3 bits to 2 trits.
func convPolyBinaryToTrinaryHelper(maxOffset, offset int, poly []int16, b int) {
	var a1, a2 int16
	switch b & 0x07 {
	case 0:
		a1, a2 = 0, 0
	case 1:
		a1, a2 = 0, 1
	case 2:
		a1, a2 = 0, -1
	case 3:
		a1, a2 = 1, 0
	case 4:
		a1, a2 = 1, 1
	case 5:
		a1, a2 = 1, -1
	case 6:
		a1, a2 = -1, 0
	case 7:
		a1, a2 = -1, 1
	}
	if offset < maxOffset {
		poly[offset] = a1
	}
	if offset+1 < maxOffset {
		poly[offset+1] = a2
	}
}

// convPolyBinaryToTrinaryHelper2 converts 24 bits stored in bits24 into 8
// trits.
func convPolyBinaryToTrinaryHelper2(maxOffset, offset int, poly []int16, bits24 int) {
	for i := 0; i < 24 && offset < maxOffset; i += 3 {
		shift := uint(24 - (i + 3))
		convPolyBinaryToTrinaryHelper(maxOffset, offset, poly, bits24>>shift)
		offset += 2
	}
}

// convPolyBinaryToTrinary converts a binary polynomial stored as a bit-packed
// array into a trinomial with coefficients [-1, 0, 1] stored as an slice of
// int16s.
func convPolyBinaryToTrinary(outputDegree int, bin []byte) []int16 {
	tri := make([]int16, outputDegree)
	blocks := len(bin) / 3
	remainder := len(bin) % 3

	// Perform the bulk of the conversion in 3-byte blocks.
	// 3 bytes == 24 bits --> 16 trits.
	for i := 0; i < blocks; i++ {
		val := int(bin[i*3])<<16 | int(bin[i*3+1])<<8 | int(bin[i*3+2])
		convPolyBinaryToTrinaryHelper2(outputDegree, 16*i, tri, val)
	}

	// Convert any partial block left at the end of the input buffer
	val := 0
	if remainder > 0 {
		val |= int(bin[blocks*3]) << 16
	}
	if remainder > 1 {
		val |= int(bin[blocks*3+1]) << 8
	}
	convPolyBinaryToTrinaryHelper2(outputDegree, 16*blocks, tri, val)

	return tri
}

// convPolyTritToBitHelper converts 2 trits to 3 bits, using the mapping
// defined in X9.92.
func convPolyTritToBitHelper(t1, t2 int16) byte {
	if t1 == -1 {
		t1 = 2
	}
	if t2 == -1 {
		t2 = 2
	}
	switch (t1 << 2) | t2 {
	case 0:
		return 0x00 // (t1,t2)=(  0,  0) ==> t = 0000
	case 1:
		return 0x01 // (t1,t2)=(  0,  1) ==> t = 0001
	case 2:
		return 0x02 // (t1,t2)=(  0, -1) ==> t = 0010
	case 4:
		return 0x03 // (t1,t2)=(  1,  0) ==> t = 0100
	case 5:
		return 0x04 // (t1,t2)=(  1,  1) ==> t = 0101
	case 6:
		return 0x05 // (t1,t2)=(  1, -1) ==> t = 0110
	case 8:
		return 0x06 // (t1,t2)=( -1,  0) ==> t = 1000
	case 9:
		return 0x07 // (t1,t2)=( -1,  1) ==> t = 1001
	default:
		return 0xff // (t1,t2)=( -1, -1) ==> t = 1010 (0xff)
	}
}

// convPolyTritToBitHelper2 converts 2 trits out of an array into a 3 bit value.
func convPolyTritToBitHelper2(offset int, trit []int16) byte {
	var t1, t2 int16
	if offset < len(trit) {
		t1 = trit[offset]
	}
	if offset+1 < len(trit) {
		t2 = trit[offset+1]
	}
	return convPolyTritToBitHelper(t1, t2)
}

// convPolyTrinaryToBinaryBlockHelper converts an array of 16 trits to 1 block
// (24 bits).
func convPolyTrinaryToBinaryBlockHelper(tOffset int, trit []int16, bOffset int, bits []byte) {
	a1 := int(convPolyTritToBitHelper2(tOffset, trit))
	a2 := int(convPolyTritToBitHelper2(tOffset+2, trit))
	a3 := int(convPolyTritToBitHelper2(tOffset+4, trit))
	a4 := int(convPolyTritToBitHelper2(tOffset+6, trit))
	a5 := int(convPolyTritToBitHelper2(tOffset+8, trit))
	a6 := int(convPolyTritToBitHelper2(tOffset+10, trit))
	a7 := int(convPolyTritToBitHelper2(tOffset+12, trit))
	a8 := int(convPolyTritToBitHelper2(tOffset+14, trit))

	// XXX: The ref calling code never checks this.
	// if (a1 | a2 | a3 | a4 | a5 | a6 | a7 | a8) == 0xff {
	//	return false
	// }

	// Pack the 8 3-bit values into a single 32-bit integer.
	// This makes it easier to pull off bytes later.
	val := a1<<21 | a2<<18 | a3<<15 | a4<<12 | a5<<9 | a6<<6 | a7<<3 | a8

	// Break the integer into bytes and put into the bits[] array.
	if bOffset < len(bits) {
		bits[bOffset] = byte(val >> 16)
		bOffset++
	}
	if bOffset < len(bits) {
		bits[bOffset] = byte(val >> 8)
		bOffset++
	}
	if bOffset < len(bits) {
		bits[bOffset] = byte(val)
	}
}

// calcPolyMod4Packed calculates R mod 4 and returns the result as a bit-packed
// byte array.
func calcPolyMod4Packed(r *polynomial.Full) (r4 []byte) {
	// R4 will have 2 bits per element, 4 elements per byte.
	r4 = make([]byte, (len(r.P)+3)/4)

	var i, j int
	for ; i < len(r4)-1; i, j = i+1, j+4 {
		tmp := (r.P[j] & 0x03) << 6
		tmp |= (r.P[j+1] & 0x03) << 4
		tmp |= (r.P[j+2] & 0x03) << 2
		tmp |= r.P[j+3] & 0x03
		r4[i] = byte(tmp)
	}

	remElements := len(r.P) & 3
	if remElements > 0 {
		r4[i] |= byte(r.P[j]&0x03) << 6
	}
	if remElements > 1 {
		r4[i] |= byte(r.P[j+1]&0x03) << 4
	}
	if remElements > 2 {
		r4[i] |= byte(r.P[j+2]&0x03) << 2
	}
	return
}

// checkDm0 verifies that the trinomial p has at least dm0 -1's and at least dm0
// 0s, and at least dm0 1's.
func checkDm0(p *polynomial.Full, dm0 int16) bool {
	var numOnes, numNegOnes int16
	for _, v := range p.P {
		switch v {
		case -1:
			numNegOnes++
		case 1:
			numOnes++
		}
	}
	if numOnes < dm0 || numNegOnes < dm0 || int16(len(p.P))-(numOnes+numNegOnes) < dm0 {
		return false
	}
	return true
}

// readerToByteReader allows using any io.Reader as a io.ByteReader by wrapping
// the io.Reader with an adapter.  If the reader already implements
// io.ByteReader, then this function is a no-op.
func readerToByteReader(r io.Reader) io.ByteReader {
	if br, ok := (r).(io.ByteReader); ok {
		return br
	}
	return &byteReaderAdapter{r: r}
}

type byteReaderAdapter struct {
	r io.Reader
}

func (r *byteReaderAdapter) ReadByte() (c byte, err error) {
	// TODO: This is really inefficient, maybe buffer?  Not sure how much I
	// trust bufio to cleanup, and this is correct so it's ok for now.
	var b [1]byte
	defer func() {
		b[0] = 0
	}()
	if _, err = r.r.Read(b[:]); err != nil {
		return
	}
	c = b[0]
	return
}

// bufByteRdWriter is a minimal io.Byte[Read,Writer] implementation that modifies
// an existing slice in place.  Interlacing ReadByte and WriteByte calls will
// lead to bad things happening.
type bufByteRdWriter struct {
	b   []byte
	off int
}

func (b *bufByteRdWriter) WriteByte(c byte) (err error) {
	if b.off+1 > len(b.b) {
		// This should *NEVER* happen.
		return io.ErrShortWrite
	}
	b.b[b.off] = c
	b.off++
	return nil
}

func (b *bufByteRdWriter) ReadByte() (c byte, err error) {
	if b.off > len(b.b) {
		return 0, io.ErrUnexpectedEOF
	}
	c = b.b[b.off]
	b.off++
	return
}

func init() {
	// All current parameter sets use Q = 2048, so they can share the inverter.
	invMod2 := []int16{0, 1}
	inverterMod2048 = polynomial.NewInverterModPowerOfPrime(2048, 2, invMod2)
}

var _ crypto.PublicKey = (*PublicKey)(nil)
var _ crypto.PrivateKey = (*PrivateKey)(nil)
