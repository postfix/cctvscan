package geo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IPInfo represents IP location information
type IPInfo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Postal   string `json:"postal"`
	Location string `json:"loc"` // "lat,lon"
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
}

// GetIPInfo retrieves IP location information from ipinfo.io
func GetIPInfo(ip string) (*IPInfo, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &info, nil
}

// FormatIPInfo formats IP information for display
func FormatIPInfo(info *IPInfo) string {
	if info == nil {
		return "No location information available"
	}

	result := fmt.Sprintf("IP: %s\n", info.IP)
	if info.Org != "" {
		result += fmt.Sprintf("ISP: %s\n", info.Org)
	}

	if info.Location != "" {
		result += fmt.Sprintf("Coordinates: %s\n", info.Location)
		result += fmt.Sprintf("Google Maps: https://www.google.com/maps?q=%s\n", info.Location)
		result += fmt.Sprintf("Google Earth: https://earth.google.com/web/@%s,0a,1000d,35y,0h,0t,0r\n", info.Location)
	}

	if info.City != "" || info.Region != "" || info.Country != "" {
		result += "Geographic Details:\n"
		if info.City != "" {
			result += fmt.Sprintf("  City: %s\n", info.City)
		}
		if info.Region != "" {
			result += fmt.Sprintf("  Region: %s\n", info.Region)
		}
		if info.Country != "" {
			result += fmt.Sprintf("  Country: %s\n", info.Country)
		}
		if info.Postal != "" {
			result += fmt.Sprintf("  Postal Code: %s\n", info.Postal)
		}
	}

	if info.Timezone != "" {
		result += fmt.Sprintf("Timezone: %s\n", info.Timezone)
	}

	return result
}
