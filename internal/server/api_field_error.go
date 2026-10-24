package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Refusals that name the field at fault (design 32 R6). An editor reads
// APIError.Field, a path into the request's JSON body, and focuses and marks
// that field instead of leaving the operator to find it from the message.
//
// A handler wraps a validation error with fieldError where the field is
// known; writeError copies the path into the body. A refusal that wraps no
// field answers as before, so the field is additive. versionConflict is the
// answer to a save that named a stale version: a 409 whose code tells an
// editor to read the object again and offer to keep its draft.

// fieldAPIError is err, about the request field at path.
type fieldAPIError struct {
	path string
	err  error
}

func (e fieldAPIError) Error() string { return e.err.Error() }

func (e fieldAPIError) Unwrap() error { return e.err }

// APIErrorField is the path writeError sends as APIError.Field.
func (e fieldAPIError) APIErrorField() string { return e.path }

// fieldError marks err as caused by the request field at path: object keys
// joined by dots, array elements as [index] ("targets.exclude[1]"). An
// error that already names a deeper field keeps it, so a helper that knows
// the element can tag it and its caller can tag the list. A nil err stays
// nil.
func fieldError(path string, err error) error {
	if err == nil {
		return nil
	}
	if apiErrorField(err) != "" {
		return err
	}
	return fieldAPIError{path: path, err: err}
}

// refieldError is err about the field at path, whatever field err named:
// for a caller whose request names the field differently from the helper
// that refused it.
func refieldError(path string, err error) error {
	return fieldAPIError{path: path, err: err}
}

// rawIndexPath is the path of the first element of raw, the list as the
// request sent it, that reads id once trimmed, or the list's path when none
// does: a refusal found on the cleaned list still points at what was sent.
func rawIndexPath(path string, raw []string, id string) string {
	for i, v := range raw {
		if strings.TrimSpace(v) == id {
			return fieldIndex(path, i)
		}
	}
	return path
}

// fieldErrorf is fieldError over a formatted message.
func fieldErrorf(path, format string, args ...any) error {
	return fieldAPIError{path: path, err: fmt.Errorf(format, args...)}
}

// fieldIndex is the path of element i of the list at path.
func fieldIndex(path string, i int) string {
	return fmt.Sprintf("%s[%d]", path, i)
}

// apiErrorField is the field path err carries, empty when it names none.
func apiErrorField(err error) string {
	var field interface{ APIErrorField() string }
	if errors.As(err, &field) {
		return field.APIErrorField()
	}
	return ""
}

// versionConflict is err as a lost save race: it answers 409 with the
// version_conflict code, whatever else the handler's 409s carry.
func versionConflict(err error) error {
	return codedAPIError{code: model.APIErrorVersionConflict, err: err}
}
