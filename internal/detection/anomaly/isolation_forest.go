package anomaly

import (
	"math"
	"math/rand"
	"sync"
)

// Point represents a feature vector for an observable entity.
type Point []float64

// iNode represents an internal or leaf node in an Isolation Tree.
type iNode struct {
	splitFeature int
	splitValue   float64
	left         *iNode
	right        *iNode
	size         int
	isLeaf       bool
}

// IsolationTree represents an individual random partition tree.
type IsolationTree struct {
	root *iNode
}

// buildTree constructs an isolation tree up to maxDepth.
func buildTree(data []Point, currentDepth int, maxDepth int) *iNode {
	if currentDepth >= maxDepth || len(data) <= 1 {
		return &iNode{size: len(data), isLeaf: true}
	}

	numFeatures := len(data[0])
	splitFeature := rand.Intn(numFeatures) // #nosec G404

	minVal := data[0][splitFeature]
	maxVal := data[0][splitFeature]
	for _, p := range data {
		if p[splitFeature] < minVal {
			minVal = p[splitFeature]
		}
		if p[splitFeature] > maxVal {
			maxVal = p[splitFeature]
		}
	}

	if minVal == maxVal {
		return &iNode{size: len(data), isLeaf: true}
	}

	splitVal := minVal + rand.Float64()*(maxVal-minVal) // #nosec G404

	var leftData, rightData []Point
	for _, p := range data {
		if p[splitFeature] < splitVal {
			leftData = append(leftData, p)
		} else {
			rightData = append(rightData, p)
		}
	}

	return &iNode{
		splitFeature: splitFeature,
		splitValue:   splitVal,
		left:         buildTree(leftData, currentDepth+1, maxDepth),
		right:        buildTree(rightData, currentDepth+1, maxDepth),
		size:         len(data),
		isLeaf:       false,
	}
}

// pathLength calculates the traversal depth of a sample point in the tree.
func (t *IsolationTree) pathLength(p Point, currentDepth float64) float64 {
	node := t.root
	depth := currentDepth

	for node != nil && !node.isLeaf {
		if p[node.splitFeature] < node.splitValue {
			node = node.left
		} else {
			node = node.right
		}
		depth++
	}

	if node != nil && node.size > 1 {
		depth += cFactor(node.size)
	}
	return depth
}

// cFactor computes the average path length of unsuccessful searches in a binary search tree.
func cFactor(n int) float64 {
	if n <= 1 {
		return 0.0
	}
	if n == 2 {
		return 1.0
	}
	// Euler-Mascheroni constant ≈ 0.5772156649
	return 2.0*(math.Log(float64(n-1))+0.5772156649) - (2.0 * float64(n-1) / float64(n))
}

// IsolationForest encapsulates an ensemble of isolation trees for anomaly scoring.
type IsolationForest struct {
	trees     []*IsolationTree
	numTrees  int
	subsample int
	training  []Point
	isTrained bool
	mu        sync.RWMutex
}

// NewIsolationForest creates an Isolation Forest model.
func NewIsolationForest(numTrees int, subsample int) *IsolationForest {
	if numTrees <= 0 {
		numTrees = 50
	}
	if subsample <= 0 {
		subsample = 128
	}
	return &IsolationForest{
		numTrees:  numTrees,
		subsample: subsample,
		training:  make([]Point, 0, subsample*2),
	}
}

// Train fits the forest on the provided dataset.
func (f *IsolationForest) Train(data []Point) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(data) == 0 {
		return
	}

	maxDepth := int(math.Ceil(math.Log2(float64(f.subsample))))
	f.trees = make([]*IsolationTree, f.numTrees)

	for i := 0; i < f.numTrees; i++ {
		sample := samplePoints(data, f.subsample)
		root := buildTree(sample, 0, maxDepth)
		f.trees[i] = &IsolationTree{root: root}
	}
	f.isTrained = true
}

func samplePoints(data []Point, n int) []Point {
	if len(data) <= n {
		return data
	}
	perm := rand.Perm(len(data)) // #nosec G404
	sample := make([]Point, n)
	for i := 0; i < n; i++ {
		sample[i] = data[perm[i]]
	}
	return sample
}

// AnomalyScore computes an anomaly score between 0.0 and 1.0.
// Scores close to 1.0 indicate anomalies; scores significantly below 0.5 are normal.
func (f *IsolationForest) AnomalyScore(p Point) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.isTrained || len(f.trees) == 0 {
		return 0.0
	}

	var totalLength float64
	for _, tree := range f.trees {
		totalLength += tree.pathLength(p, 0)
	}
	meanLength := totalLength / float64(len(f.trees))
	c := cFactor(f.subsample)
	if c == 0 {
		return 0.5
	}

	return math.Pow(2.0, -meanLength/c)
}
