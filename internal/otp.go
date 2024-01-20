package internal

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

type (
	Payload struct {
		OtpParameters []OtpParameter
		Version       int32
		BatchSize     int32
		BatchIndex    int32
		BatchId       int32
	}

	OtpParameter interface {
		Data() OtpParameterData
		Bytes() []byte
	}

	OtpParameterData struct {
		Secret        []byte
		Name          string
		Issuer        string
		Algorithm     func() hash.Hash
		AlgorithmName string
		Digits        int
		Type          OtpParameterType
		Counter       uint64
	}

	OtpParameterType struct {
		IsTotp bool
		IsHotp bool
	}

	Otp struct {
		Code      string
		ExpiresAt time.Time
	}
)

const (
	offset = 5 * time.Second
	period = 30 * time.Second

	codeFailed = "failed"
)

func (op OtpParameterData) Generate() (string, error) {
	if !op.Type.IsTotp {
		return codeFailed, fmt.Errorf("only totp is supported")
	}

	var count = func() uint64 {
		switch {
		case op.Type.IsHotp:
			op.Counter++ // pre-increment; rfc4226 section 7.2.
			return op.Counter
		case op.Type.IsTotp:
			now := time.Now().Add(offset)
			cnt := uint64(now.Unix()) / uint64(period.Seconds())
			return cnt
		}

		panic("unknown otp type")
	}

	h := hmac.New(op.Algorithm, op.Secret)
	binary.Write(h, binary.BigEndian, count())
	hashed := h.Sum(nil)
	offset := hashed[h.Size()-1] & 15
	result := binary.BigEndian.Uint32(hashed[offset:]) & (1<<31 - 1)
	code := int(result) % int(math.Pow10(op.Digits))

	return fmt.Sprintf("%0*d", op.Digits, code), nil
}
