package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyAuth(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name       string
		apiKey     string
		headerKey  string
		wantStatus int
	}{
		{
			name:       "empty configured key permits all",
			apiKey:     "",
			headerKey:  "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "valid API key matches",
			apiKey:     "secret-token-123",
			headerKey:  "secret-token-123",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing header returns 401",
			apiKey:     "secret-token-123",
			headerKey:  "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong key returns 401",
			apiKey:     "secret-token-123",
			headerKey:  "wrong-token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := APIKeyAuth(tt.apiKey)
			handler := mw(dummyHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.headerKey != "" {
				req.Header.Set("X-API-Key", tt.headerKey)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("APIKeyAuth status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
