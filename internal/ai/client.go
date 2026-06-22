package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/thrive-spectrexq/r3trive/internal/config"
)

// Client represents an AI backend client capable of chatting.
type Client interface {
	Chat(ctx context.Context, prompt string) (string, error)
}

// NewClient creates an AI client based on the configuration.
func NewClient(cfg config.AIConfig) (Client, error) {
	switch cfg.Backend {
	case "ollama":
		return &OllamaClient{
			Endpoint: cfg.Endpoint,
			Model:    cfg.Model,
			client:   &http.Client{Timeout: 60 * time.Second},
		}, nil
	case "openai":
		return &OpenAIClient{
			Endpoint: cfg.Endpoint,
			Model:    cfg.Model,
			client:   &http.Client{Timeout: 60 * time.Second},
		}, nil
	case "none", "":
		return nil, errors.New("ai backend is disabled")
	default:
		return nil, fmt.Errorf("unsupported ai backend: %s", cfg.Backend)
	}
}

// OllamaClient interacts with a local or remote Ollama instance.
type OllamaClient struct {
	Endpoint string
	Model    string
	client   *http.Client
}

// Chat sends a prompt to Ollama and returns the response.
func (c *OllamaClient) Chat(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/api/generate", c.Endpoint)

	reqBody := map[string]interface{}{
		"model":  c.Model,
		"prompt": prompt,
		"stream": false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(body))
	}

	var resData struct {
		Response string `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&resData); err != nil {
		return "", err
	}

	return resData.Response, nil
}

// OpenAIClient interacts with the OpenAI API or an OpenAI-compatible endpoint.
type OpenAIClient struct {
	Endpoint string
	Model    string
	client   *http.Client
}

// Chat sends a prompt to OpenAI and returns the response.
func (c *OpenAIClient) Chat(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/v1/chat/completions", c.Endpoint)

	reqBody := map[string]interface{}{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"stream": false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	// If authorization is needed, it could be loaded from env or config.
	// req.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_API_KEY"))

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("openai API error (status %d): %s", resp.StatusCode, string(body))
	}

	var resData struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&resData); err != nil {
		return "", err
	}

	if len(resData.Choices) == 0 {
		return "", errors.New("empty response from openai")
	}

	return resData.Choices[0].Message.Content, nil
}
