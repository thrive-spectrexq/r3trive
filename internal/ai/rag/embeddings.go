package rag

import (
	"math"
	"strings"
)

// Embedder defines an interface for generating text embeddings.
type Embedder interface {
	Embed(text string) ([]float64, error)
}

// MockEmbedder provides a simple local embedding implementation using a bag-of-words approach
// for a small hardcoded vocabulary of security terms.
type MockEmbedder struct {
	vocabulary []string
}

// NewMockEmbedder creates a new MockEmbedder.
func NewMockEmbedder() *MockEmbedder {
	return &MockEmbedder{
		vocabulary: []string{
			"process", "registry", "network", "injection", "malware",
			"powershell", "lsass", "c2", "beacon", "persistence",
		},
	}
}

// Embed generates a frequency vector for the text based on the vocabulary.
func (e *MockEmbedder) Embed(text string) ([]float64, error) {
	textLower := strings.ToLower(text)
	vec := make([]float64, len(e.vocabulary))
	
	for i, term := range e.vocabulary {
		count := strings.Count(textLower, term)
		vec[i] = float64(count)
	}
	
	// Normalize the vector
	var norm float64
	for _, val := range vec {
		norm += val * val
	}
	norm = math.Sqrt(norm)
	
	if norm > 0 {
		for i := range vec {
			vec[i] /= norm
		}
	}
	
	return vec, nil
}

// CosineSimilarity calculates the cosine similarity between two vectors.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0.0
	}
	
	var dotProduct float64
	var normA float64
	var normB float64
	
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	
	if normA == 0 || normB == 0 {
		return 0.0
	}
	
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
