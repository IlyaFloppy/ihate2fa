package vault

import (
	"errors"
	"fmt"

	"github.com/IlyaFloppy/ihate2fa/internal"
	"github.com/keybase/go-keychain"
)

type Store struct {
	parser parser
}

type parser interface {
	Parse(link string) (internal.Payload, error)
	FromProtoBytes(bytes []byte) (internal.OtpParameter, error)
}

func NewStore(parser parser) *Store {
	return &Store{
		parser: parser,
	}
}

const (
	serviceName = "IHate2FAService"
	labelPrefix = "ihate2fa: "
)

func (s Store) Add(param internal.OtpParameter) error {
	paramData := param.Data()
	protoBytes := param.Bytes()

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(serviceName)
	item.SetAccount(paramData.Name)
	item.SetLabel(labelPrefix + paramData.Name)
	item.SetDescription("OTP")
	item.SetData(protoBytes)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(item)
	if err != nil {
		return fmt.Errorf("failed to add item to a keychain: %w", err)
	}

	return nil
}

func (s Store) List() ([]internal.OtpParameter, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(serviceName)
	query.SetMatchLimit(keychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query item from keychain: %w", err)
	}

	res := make([]internal.OtpParameter, 0, len(results))
	for _, r := range results {
		data, err := s.getData(serviceName, r.Account)
		if err != nil {
			return nil, fmt.Errorf("failed to get keychain item data: %w", err)
		}

		op, err := s.parser.FromProtoBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse item from keychain: %w", err)
		}

		res = append(res, op)
	}

	return res, nil
}

func (s Store) Get(account string) (internal.OtpParameter, error) {
	data, err := s.getData(serviceName, account)
	if err != nil {
		return nil, fmt.Errorf("failed to get keychain item data: %w", err)
	}

	op, err := s.parser.FromProtoBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse item from keychain: %w", err)
	}

	return op, nil
}

func (s Store) getData(service string, account string) ([]byte, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query item from keychain: %w", err)
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("unexpected query results len: %d", len(results))
	}

	return results[0].Data, nil
}

func (s Store) Clean() error {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(serviceName)
	query.SetMatchLimit(keychain.MatchLimitAll)
	err := keychain.DeleteItem(query)
	if err != nil {
		if errors.Is(err, keychain.ErrorItemNotFound) {
			return nil
		}
		return fmt.Errorf("failed to delete item from keychain: %w", err)
	}

	return nil
}
