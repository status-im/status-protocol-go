package statusproto

import (
	"strings"

	"github.com/pkg/errors"

	encryptmigrations "github.com/status-im/status-protocol-go/encryption/migrations"
	"github.com/status-im/status-protocol-go/migrations"
	transpmigrations "github.com/status-im/status-protocol-go/transport/whisper/migrations"
)

type getter func(string) ([]byte, error)

func prepareMigrations() ([]string, getter, error) {
	var allNames []string
	nameToGetter := make(map[string]getter)

	allMigrations := []struct {
		Names  []string
		Getter getter
	}{
		{
			Names:  transpmigrations.AssetNames(),
			Getter: transpmigrations.Asset,
		},
		{
			Names:  encryptmigrations.AssetNames(),
			Getter: encryptmigrations.Asset,
		},
		{
			Names:  migrations.AssetNames(),
			Getter: migrations.Asset,
		},
	}

	for _, m := range allMigrations {
		for _, name := range m.Names {
			if !validateName(name) {
				continue
			}

			if _, ok := nameToGetter[name]; ok {
				return nil, nil, errors.Errorf("migration with name %s already exists", name)
			}
			allNames = append(allNames, name)
			nameToGetter[name] = m.Getter
		}
	}

	return allNames, func(name string) ([]byte, error) {
		getter, ok := nameToGetter[name]
		if !ok {
			return nil, errors.Errorf("no migration for name %s", name)
		}
		return getter(name)
	}, nil
}

// validateName verifies that only *.sql files are taken into consideration.
func validateName(name string) bool {
	return strings.HasSuffix(name, ".sql")
}
