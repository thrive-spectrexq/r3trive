package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/response"
)

type mockActionExecutor struct {
	executeFn func(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error)
}

func (m *mockActionExecutor) Execute(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error) {
	if m.executeFn != nil {
		return m.executeFn(ctx, action, params)
	}
	return response.ActionResult{
		Action:    action,
		Success:   true,
		Message:   "executed mock",
		Timestamp: time.Now().UTC(),
	}, nil
}

func TestExecuteAction_InvalidBody(t *testing.T) {
	handler := ExecuteAction(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/execute", bytes.NewBufferString("{invalid-json"))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestExecuteAction_MissingAction(t *testing.T) {
	handler := ExecuteAction(nil, nil)
	payload := ExecuteActionRequest{
		Params: map[string]any{"pid": 1234},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/execute", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestExecuteAction_NoExecutor(t *testing.T) {
	handler := ExecuteAction(nil, nil)
	payload := ExecuteActionRequest{
		Action: "kill_process",
		Params: map[string]any{"pid": 1234},
		DryRun: true,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/execute", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "accepted" {
		t.Fatalf("expected status 'accepted', got %v", resp["status"])
	}
}

func TestExecuteAction_WithExecutor_Success(t *testing.T) {
	mockExec := &mockActionExecutor{
		executeFn: func(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error) {
			if action != response.ActionKillProcess {
				t.Fatalf("expected action %s, got %s", response.ActionKillProcess, action)
			}
			return response.ActionResult{
				Action:     action,
				Success:    true,
				Message:    "process terminated",
				Timestamp:  time.Now().UTC(),
				Reversible: false,
			}, nil
		},
	}

	handler := ExecuteAction(nil, mockExec)
	payload := ExecuteActionRequest{
		Action: string(response.ActionKillProcess),
		Params: map[string]any{"pid": 4321},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/execute", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "executed" {
		t.Fatalf("expected status 'executed', got %v", resp["status"])
	}
}

func TestExecuteAction_WithExecutor_Error(t *testing.T) {
	mockExec := &mockActionExecutor{
		executeFn: func(ctx context.Context, action response.ActionType, params map[string]any) (response.ActionResult, error) {
			return response.ActionResult{}, errors.New("action execution failed")
		},
	}

	handler := ExecuteAction(nil, mockExec)
	payload := ExecuteActionRequest{
		Action: string(response.ActionKillProcess),
		Params: map[string]any{"pid": 4321},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/response/execute", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "action execution failed" {
		t.Fatalf("expected error message 'action execution failed', got %v", resp["error"])
	}
}
