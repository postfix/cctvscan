package fingerprint

import "testing"

func TestDetect(t *testing.T) {
	b, _ := Detect("Server: HiKVISION-xxx", "", "")
	if b != "Hikvision" {
		t.Fatalf("want Hikvision, got %s", b)
	}
	if len(CVEsForBrand(b)) == 0 {
		t.Fatal("expected CVEs")
	}
}

func TestDetectWithVersion(t *testing.T) {
	// Test Hikvision with version
	result := DetectWithVersion("Server: HiKVISION-WebService/1.0", "Hikvision Web Service v4.1.2", "")
	if result.Brand != "Hikvision" {
		t.Fatalf("want Hikvision, got %s", result.Brand)
	}
	if result.Version != "4.1.2" {
		t.Fatalf("want version 4.1.2, got %s", result.Version)
	}
}

func TestWebContentAnalysis(t *testing.T) {
	// Test web content analysis
	htmlContent := `<html><head><title>Hikvision Web Service v3.4.5</title></head><body>Hikvision Login Page</body></html>`
	result := AnalyzeWebContent(htmlContent)
	if result.Brand != "Hikvision" {
		t.Fatalf("want Hikvision from web content, got %s", result.Brand)
	}
}

func TestVersionExtraction(t *testing.T) {
	// Test version extraction
	version := extractVersion("Hikvision Web Service v4.1.2", "Hikvision")
	if version != "4.1.2" {
		t.Fatalf("want version 4.1.2, got %s", version)
	}
}

func TestSoftwareInfoExtraction(t *testing.T) {
	// Test software info extraction
	content := "Firmware: v2.1.3, Software: v1.0.5, Build: 2023.12.15"
	info := ExtractSoftwareInfo(content)

	if info["firmware"] != "2.1.3" {
		t.Fatalf("want firmware 2.1.3, got %s", info["firmware"])
	}
	if info["software"] != "1.0.5" {
		t.Fatalf("want software 1.0.5, got %s", info["software"])
	}
}

func TestLoginSystemDetection(t *testing.T) {
	// Test login system detection
	content := `<html><body>Hikvision Login Page - login.jsp</body></html>`
	system := DetectLoginSystem(content)
	if system != "Hikvision" {
		t.Fatalf("want Hikvision login system, got %s", system)
	}
}

func TestTitlePatternMatching(t *testing.T) {
	// Test title pattern matching
	htmlContent := `<html><head><title>Dahua DSS v3.2.1</title></head><body>Login</body></html>`
	result := DetectWithVersion("", htmlContent, "")
	if result.Brand != "Dahua" {
		t.Fatalf("want Dahua from title, got %s", result.Brand)
	}
}
