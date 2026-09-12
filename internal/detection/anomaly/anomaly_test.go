package anomaly

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestBeaconingCVAnalysis(t *testing.T) {
	tracker := NewBeaconTracker(20)

	// Simulate periodic beaconing at 1-second intervals with tiny jitter
	base := time.Now()
	for i := 0; i < 15; i++ {
		// Interval between 0.98s and 1.02s
		jitter := float64(i%3) * 0.01
		tracker.Record(base.Add(time.Duration(float64(i)+jitter) * time.Second))
	}

	metrics := tracker.Analyze(0.15)
	if !metrics.IsBeacon {
		t.Fatalf("expected periodic traffic to be flagged as beacon, got metrics: %+v", metrics)
	}
	if metrics.CV > 0.15 {
		t.Fatalf("expected CV <= 0.15, got: %f", metrics.CV)
	}

	// Simulate random human web browsing with high jitter
	randomTracker := NewBeaconTracker(20)
	for i := 0; i < 15; i++ {
		sec := (i * 7) % 19
		randomTracker.Record(base.Add(time.Duration(sec*10) * time.Second))
	}
	randMetrics := randomTracker.Analyze(0.15)
	if randMetrics.IsBeacon {
		t.Fatalf("random traffic should NOT be flagged as beacon, got metrics: %+v", randMetrics)
	}
}

func TestDNSTunnelingDetection(t *testing.T) {
	detector := NewDNSTunnelDetector(3.5)

	// Standard corporate query
	normalResult := detector.EvaluateQuery("mail.google.com")
	if normalResult.IsTunnelSuspect {
		t.Fatalf("normal DNS query was falsely flagged: %+v", normalResult)
	}

	// High entropy base64 encoded exfiltration subdomain
	tunnelingFQDN := "dGhpcyBpcyBhbiBhY3R1YWwgZXhmaWx0cmF0aW9uIHBheWxvYWQu.c2.attacker.com"
	tunnelResult := detector.EvaluateQuery(tunnelingFQDN)
	if !tunnelResult.IsTunnelSuspect {
		t.Fatalf("DNS tunneling query was NOT flagged: %+v", tunnelResult)
	}
	if tunnelResult.Entropy < 3.5 {
		t.Fatalf("expected high entropy for base64 subdomain, got: %f", tunnelResult.Entropy)
	}
}

func TestRansomwareDetection(t *testing.T) {
	detector := NewRansomwareDetector(5*time.Second, 10, 7.0)

	pid := 4420

	// 1. Normal text file modifications (low entropy)
	for i := 0; i < 5; i++ {
		plainText := []byte("Hello world, this is a normal log file entry with low entropy repetitive text.")
		alert := detector.RecordMutation(pid, "C:\\Users\\test\\file.txt", plainText, false)
		if alert.IsRansomware {
			t.Fatalf("normal text write should not trigger ransomware alert")
		}
	}

	// 2. High-entropy encrypted buffers (ransomware mass encryption)
	for i := 0; i < 12; i++ {
		encryptedBuf := make([]byte, 256)
		_, _ = rand.Read(encryptedBuf)
		alert := detector.RecordMutation(pid, "C:\\Users\\test\\doc.locked", encryptedBuf, true)
		if i >= 9 && !alert.IsRansomware {
			t.Fatalf("expected ransomware alert after threshold reached, got: %+v", alert)
		}
	}
}

func TestIsolationForestAndBaseline(t *testing.T) {
	forest := NewIsolationForest(30, 32)

	// Create normal clustered training data
	var trainingData []Point
	for i := 0; i < 50; i++ {
		trainingData = append(trainingData, Point{float64(i % 5), float64(i % 10)})
	}
	forest.Train(trainingData)

	normalPoint := Point{2.0, 4.0}
	normalScore := forest.AnomalyScore(normalPoint)

	outlierPoint := Point{999.0, 999.0}
	outlierScore := forest.AnomalyScore(outlierPoint)

	if outlierScore <= normalScore {
		t.Fatalf("expected outlier score (%f) to be greater than normal score (%f)", outlierScore, normalScore)
	}

	// Test baseline manager
	bm := NewBaselineManager(1 * time.Hour)
	if !bm.IsLearning() {
		t.Fatalf("expected baseline manager to be in learning state")
	}

	isNew, _ := bm.RecordProcessEvent("host-01", "svchost.exe")
	if !isNew {
		t.Fatalf("first occurrence should be marked as isNew")
	}

	isNewSecond, _ := bm.RecordProcessEvent("host-01", "svchost.exe")
	if isNewSecond {
		t.Fatalf("second occurrence should not be marked as isNew")
	}
}
