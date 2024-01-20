package migration

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/url"
	"strings"

	"github.com/IlyaFloppy/ihate2fa/internal"
	"google.golang.org/protobuf/proto"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative migration.proto

type (
	Parser struct{}

	otpParameterImpl struct {
		internal.OtpParameterData
		bytes []byte
	}
)

func NewParser() Parser {
	return Parser{}
}

func (op *otpParameterImpl) Data() internal.OtpParameterData {
	return op.OtpParameterData
}

func (op *otpParameterImpl) Bytes() []byte {
	return op.bytes
}

func (p Parser) FromProtoBytes(bytes []byte) (internal.OtpParameter, error) {
	var op Payload_OtpParameters
	err := proto.Unmarshal(bytes, &op)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal otp parameter")
	}

	data := internal.OtpParameterData{
		Secret:        op.Secret,
		Name:          op.Name,
		Issuer:        op.Issuer,
		Algorithm:     hashByAlgorithm(op.Algorithm),
		AlgorithmName: nameByAlgorithm(op.Algorithm),
		Digits:        countDigits(op.Digits),
		Type: internal.OtpParameterType{
			IsTotp: false ||
				op.Type == Payload_OtpParameters_OTP_TYPE_TOTP ||
				op.Type == Payload_OtpParameters_OTP_TYPE_UNSPECIFIED,
			IsHotp: false ||
				op.Type == Payload_OtpParameters_OTP_TYPE_HOTP,
		},
		Counter: op.Counter,
	}

	return &otpParameterImpl{
		OtpParameterData: data,
		bytes:            bytes,
	}, nil
}

func (p Parser) Parse(link string) (internal.Payload, error) {
	data, err := p.extractData(link)
	if err != nil {
		return internal.Payload{}, fmt.Errorf("failed to extract data from link: %w", err)
	}

	var pp Payload
	err = proto.Unmarshal(data, &pp)
	if err != nil {
		return internal.Payload{}, fmt.Errorf("failed to unmarshal data from link: %w", err)
	}

	params := make([]internal.OtpParameter, 0, len(pp.OtpParameters))
	for _, op := range pp.OtpParameters {
		bytes, err := proto.Marshal(op)
		if err != nil {
			return internal.Payload{}, fmt.Errorf("failed to marshal otp parameter: %w", err)
		}

		param, err := p.FromProtoBytes(bytes)
		if err != nil {
			return internal.Payload{}, fmt.Errorf("failed to unmarshal otp parameter: %w", err)
		}

		params = append(params, param)
	}

	return internal.Payload{
		OtpParameters: params,
		Version:       pp.Version,
		BatchSize:     pp.BatchSize,
		BatchIndex:    pp.BatchIndex,
		BatchId:       pp.BatchId,
	}, nil
}

func (p Parser) extractData(link string) ([]byte, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}

	const scheme = "otpauth-migration"
	if u.Scheme != scheme {
		return nil, fmt.Errorf("unknown scheme %q, should be %q", u.Scheme, scheme)
	}
	if u.Host != "offline" {
		return nil, fmt.Errorf("unknown host %q", u.Host)
	}
	data := u.Query().Get("data")
	data = strings.ReplaceAll(data, " ", "+")
	return base64.StdEncoding.DecodeString(data)
}

func hashByAlgorithm(algo Payload_OtpParameters_Algorithm) func() hash.Hash {
	switch algo {
	case Payload_OtpParameters_ALGORITHM_UNSPECIFIED:
		return sha1.New
	case Payload_OtpParameters_ALGORITHM_SHA1:
		return sha1.New
	case Payload_OtpParameters_ALGORITHM_SHA256:
		return sha256.New
	case Payload_OtpParameters_ALGORITHM_SHA512:
		return sha512.New
	case Payload_OtpParameters_ALGORITHM_MD5:
		return md5.New
	}

	panic("unknown algorithm: " + algo.String())
}

func nameByAlgorithm(algo Payload_OtpParameters_Algorithm) string {
	switch algo {
	case Payload_OtpParameters_ALGORITHM_UNSPECIFIED:
		return "SHA1"
	case Payload_OtpParameters_ALGORITHM_SHA1:
		return "SHA1"
	case Payload_OtpParameters_ALGORITHM_SHA256:
		return "SHA256"
	case Payload_OtpParameters_ALGORITHM_SHA512:
		return "SHA512"
	case Payload_OtpParameters_ALGORITHM_MD5:
		return "MD5"
	}

	panic("unknown algorithm: " + algo.String())
}

func countDigits(digits Payload_OtpParameters_DigitCount) int {
	switch digits {
	case Payload_OtpParameters_DIGIT_COUNT_UNSPECIFIED:
		return 6
	case Payload_OtpParameters_DIGIT_COUNT_SIX:
		return 6
	case Payload_OtpParameters_DIGIT_COUNT_EIGHT:
		return 8
	}

	panic("unknown digits: " + digits.String())
}
