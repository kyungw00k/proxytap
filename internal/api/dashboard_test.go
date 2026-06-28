package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleDashboard_ServesEmbeddedHTML(t *testing.T) {
	srv := New("127.0.0.1:0", nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), "<title>proxytap</title>") {
		t.Errorf("body missing <title>; got %d bytes", len(body))
	}
	if !strings.Contains(string(body), "id=\"healthy-proxies\"") {
		t.Errorf("body missing healthy-proxies table")
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q; want text/html", rec.Header().Get("Content-Type"))
	}
}

func TestHandleDashboard_RejectsUnknownPath(t *testing.T) {
	srv := New("127.0.0.1:0", nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	srv.handleDashboard(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}
