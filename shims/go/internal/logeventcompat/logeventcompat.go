// Package logeventcompat bridges the lifecycle event field rename while the
// conformance workflow tests both sides of the dnsid-go change.
package logeventcompat

import (
	"fmt"
	"reflect"

	dnsidlog "github.com/dnsid-ai/dnsid-go/log"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// SetIssuance populates the role-specific issuance fields when available and
// falls back to their legacy generic names.
func SetIssuance(event *dnsidlog.LogEvent, entityKey jwk.Key, entityThumbprint string, operationalKey jwk.Key, operationalThumbprint string) {
	mustSetFirst(event, entityKey, "InitialEntityPublicKey", "EntityPublicKey")
	setIfPresent(event, entityThumbprint, "InitialEntityThumbprint")
	mustSetFirst(event, operationalKey, "InitialOperationalPublicKey", "PublicKey")
	mustSetFirst(event, operationalThumbprint, "InitialOperationalThumbprint", "Thumbprint")
}

// SetRotation populates the role-specific rotation fields when available and
// falls back to their legacy generic names.
func SetRotation(event *dnsidlog.LogEvent, previousKid, previousThumbprint, newKid string, newKey jwk.Key, newThumbprint string) {
	mustSetFirst(event, previousKid, "PreviousOperationalKid", "PreviousKid")
	mustSetFirst(event, previousThumbprint, "PreviousOperationalThumbprint", "PreviousThumbprint")
	mustSetFirst(event, newKid, "NewOperationalKid", "NewKid")
	mustSetFirst(event, newKey, "NewOperationalPublicKey", "NewPublicKey")
	mustSetFirst(event, newThumbprint, "NewOperationalThumbprint", "NewThumbprint")
}

func mustSetFirst(event *dnsidlog.LogEvent, value any, names ...string) {
	if setIfPresent(event, value, names...) {
		return
	}
	panic(fmt.Sprintf("dnsid compliance shim: LogEvent has none of fields %v", names))
}

func setIfPresent(event *dnsidlog.LogEvent, value any, names ...string) bool {
	elem := reflect.ValueOf(event).Elem()
	for _, name := range names {
		field := elem.FieldByName(name)
		if !field.IsValid() {
			continue
		}
		if value == nil {
			field.Set(reflect.Zero(field.Type()))
		} else {
			field.Set(reflect.ValueOf(value))
		}
		return true
	}
	return false
}
