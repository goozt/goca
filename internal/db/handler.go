package db

import (
	"net/http"

	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func HandlerListRevocations(w http.ResponseWriter, r *http.Request) {
	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"crl_number": caDB.GetCRLNumber(),
		"issued":     caDB.ListIssued(),
		"revoked":    caDB.ListRevocations(),
	})
}
