package scim

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/fleetdm/fleet/v4/server/fleet"
)

type alreadyExistsError interface {
	IsAlreadyExists() bool
}

func uintString(value uint) string {
	return strconv.FormatUint(uint64(value), 10)
}

func (p *provider) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	if fleet.IsNotFound(err) {
		writeSCIMError(w, http.StatusNotFound, "SCIM resource not found", "")
		return
	}
	var validationErr *fleet.SCIMValidationError
	if errors.As(err, &validationErr) {
		writeSCIMError(w, http.StatusBadRequest, validationErr.Error(), "invalidValue")
		return
	}
	var duplicate alreadyExistsError
	if errors.As(err, &duplicate) && duplicate.IsAlreadyExists() {
		writeSCIMError(w, http.StatusConflict, "SCIM resource already exists", "uniqueness")
		return
	}
	p.logger.ErrorContext(r.Context(), "Community+ SCIM datastore error", "err", err)
	writeSCIMError(w, http.StatusInternalServerError, "SCIM datastore operation failed", "")
}
