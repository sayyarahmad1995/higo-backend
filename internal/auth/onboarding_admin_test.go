package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminAssets(t *testing.T) {
	for _, file := range []string{"", "app.mjs", "api.mjs", "style.css"} {
		recorder := httptest.NewRecorder()
		adminPage().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/"+file, nil))
		if recorder.Code != 200 || recorder.Header().Get("Cache-Control") != "no-store" ||
			!strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("bad admin response for %q: %d %v", file, recorder.Code, recorder.Header())
		}
	}
}
