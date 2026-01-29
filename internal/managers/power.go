package managers

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PowerManager handles UPS/battery monitoring for Geekworm X1202
// Uses MAX17040G+ fuel gauge IC over I2C (address 0x36)
// GPIO6 = Power loss detection (active low)
// GPIO16 = Charging control
type PowerManager struct {
	i2cBus     string
	i2cAddr    int
	gpioPower  int
	gpioCharge int
	lastStatus *UPSStatus
	statusLock sync.RWMutex
	available  bool
}

// UPSStatus represents current UPS state
type UPSStatus struct {
	Available      bool      `json:"available"`
	BatteryPercent float64   `json:"battery_percent"`
	BatteryVoltage float64   `json:"battery_voltage"`
	IsCharging     bool      `json:"is_charging"`
	OnBattery      bool      `json:"on_battery"`     // True if running on battery (AC lost)
	PowerGood      bool      `json:"power_good"`     // True if AC power present
	CellCount      int       `json:"cell_count"`     // Number of 18650 cells (4 for X1202)
	EstimatedMins  int       `json:"estimated_mins"` // Rough runtime estimate
	LastUpdated    time.Time `json:"last_updated"`
	Error          string    `json:"error,omitempty"`
}

// NewPowerManager creates a new PowerManager for X1202 UPS HAT
func NewPowerManager() *PowerManager {
	pm := &PowerManager{
		i2cBus:     "/dev/i2c-1",
		i2cAddr:    0x36, // MAX17040G+ default address
		gpioPower:  6,    // Power loss detection
		gpioCharge: 16,   // Charging control
	}

	// Check if UPS is available
	pm.available = pm.checkAvailability()

	return pm
}

// checkAvailability verifies the UPS hardware is present
func (m *PowerManager) checkAvailability() bool {
	// Check if I2C device exists
	i2cPaths := []string{
		"/dev/i2c-1",
		"/host/dev/i2c-1",
	}

	for _, path := range i2cPaths {
		if _, err := os.Stat(path); err == nil {
			m.i2cBus = path
			return true
		}
	}

	// Also check sysfs for i2c devices
	if _, err := os.Stat("/sys/class/i2c-adapter/i2c-1"); err == nil {
		return true
	}
	if _, err := os.Stat("/host/sys/class/i2c-adapter/i2c-1"); err == nil {
		return true
	}

	return false
}

// GetStatus returns current UPS status
func (m *PowerManager) GetStatus() *UPSStatus {
	status := &UPSStatus{
		Available:   m.available,
		CellCount:   4, // X1202 uses 4x 18650 cells
		LastUpdated: time.Now(),
	}

	if !m.available {
		status.Error = "UPS hardware not detected"
		return status
	}

	// Read battery voltage and percentage from MAX17040G+
	voltage, percent, err := m.readFuelGauge()
	if err != nil {
		status.Error = fmt.Sprintf("Failed to read fuel gauge: %v", err)
		// Try fallback methods
		voltage, percent = m.readFuelGaugeFallback()
	}

	status.BatteryVoltage = voltage
	status.BatteryPercent = percent

	// Read power status from GPIO
	status.PowerGood = m.readGPIO(m.gpioPower) == 1 // Active high for power good
	status.OnBattery = !status.PowerGood
	status.IsCharging = m.readGPIO(m.gpioCharge) == 1

	// Estimate runtime (rough: ~2000mAh per cell, ~5W average consumption)
	// 4 cells * 3.7V * 2Ah = ~29.6Wh, at 5W = ~6 hours at 100%
	if status.BatteryPercent > 0 {
		status.EstimatedMins = int(status.BatteryPercent * 3.6) // ~360 mins at 100%
	}

	// Cache the status
	m.statusLock.Lock()
	m.lastStatus = status
	m.statusLock.Unlock()

	return status
}

// readFuelGauge reads voltage and SOC from MAX17040G+ via I2C
func (m *PowerManager) readFuelGauge() (float64, float64, error) {
	// MAX17040G+ registers:
	// 0x02-0x03: VCELL (voltage)
	// 0x04-0x05: SOC (state of charge)
	// 0x06-0x07: MODE
	// 0x08-0x09: VERSION
	// 0xFE-0xFF: COMMAND

	// Try using i2cget command (most compatible)
	voltage, err := m.i2cReadWord(0x02)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read VCELL: %w", err)
	}

	soc, err := m.i2cReadWord(0x04)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read SOC: %w", err)
	}

	// Convert VCELL to voltage
	// VCELL is 12-bit value, upper 12 bits of 16-bit register
	// Voltage = VCELL * 1.25mV
	vcell := float64(voltage>>4) * 1.25 / 1000.0 // Convert to volts

	// For 4S battery pack, multiply by 4
	batteryVoltage := vcell * 4.0

	// Convert SOC to percentage
	// SOC register: upper byte = integer part, lower byte = 1/256th part
	socPercent := float64(soc>>8) + float64(soc&0xFF)/256.0

	// Clamp to 0-100
	if socPercent > 100 {
		socPercent = 100
	}
	if socPercent < 0 {
		socPercent = 0
	}

	return batteryVoltage, socPercent, nil
}

// i2cReadWord reads a 16-bit word from I2C register
func (m *PowerManager) i2cReadWord(reg int) (uint16, error) {
	// Try using i2cget command first
	cmd := fmt.Sprintf("i2cget -y 1 0x%02x 0x%02x w 2>/dev/null", m.i2cAddr, reg)
	output, err := runCommand("sh", "-c", cmd)
	if err == nil {
		// Parse hex output (e.g., "0x1234")
		output = strings.TrimSpace(output)
		if strings.HasPrefix(output, "0x") {
			val, err := strconv.ParseUint(output[2:], 16, 16)
			if err == nil {
				// i2cget returns bytes swapped, so swap them back
				return uint16((val&0xFF)<<8 | (val>>8)&0xFF), nil
			}
		}
	}

	// Fallback: direct I2C file operations
	return m.i2cReadWordDirect(reg)
}

// i2cReadWordDirect reads from I2C using direct file operations
func (m *PowerManager) i2cReadWordDirect(reg int) (uint16, error) {
	// Try different I2C device paths
	i2cPaths := []string{"/dev/i2c-1", "/dev/i2c-0"}

	for _, path := range i2cPaths {
		f, err := os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			continue
		}
		defer f.Close()

		// Set I2C slave address using ioctl
		// I2C_SLAVE = 0x0703
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x0703, uintptr(m.i2cAddr))
		if errno != 0 {
			continue
		}

		// Write register address
		_, err = f.Write([]byte{byte(reg)})
		if err != nil {
			continue
		}

		// Read 2 bytes
		buf := make([]byte, 2)
		n, err := f.Read(buf)
		if err != nil || n != 2 {
			continue
		}

		// Return as big-endian word
		return uint16(buf[0])<<8 | uint16(buf[1]), nil
	}

	return 0, fmt.Errorf("failed to read I2C register")
}

// readFuelGaugeFallback tries alternative methods to read battery status
func (m *PowerManager) readFuelGaugeFallback() (float64, float64) {
	// Try reading from sysfs power supply interface
	paths := []string{
		"/sys/class/power_supply/max17040",
		"/host/sys/class/power_supply/max17040",
		"/sys/class/power_supply/battery",
		"/host/sys/class/power_supply/battery",
	}

	var voltage, percent float64

	for _, basePath := range paths {
		// Read voltage
		if data, err := os.ReadFile(basePath + "/voltage_now"); err == nil {
			if v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
				voltage = v / 1000000.0 // Convert µV to V
			}
		}

		// Read capacity
		if data, err := os.ReadFile(basePath + "/capacity"); err == nil {
			if p, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
				percent = p
			}
		}

		if voltage > 0 || percent > 0 {
			break
		}
	}

	// If still no data, estimate from vcgencmd (Pi specific)
	if voltage == 0 {
		if output, err := runCommand("vcgencmd", "measure_volts", "core"); err == nil {
			// Parse "volt=1.2000V"
			parts := strings.Split(output, "=")
			if len(parts) == 2 {
				v := strings.TrimSuffix(strings.TrimSpace(parts[1]), "V")
				if val, err := strconv.ParseFloat(v, 64); err == nil {
					voltage = val * 4 // Rough estimate for 4S pack
				}
			}
		}
	}

	return voltage, percent
}

// readGPIO reads a GPIO pin value
func (m *PowerManager) readGPIO(pin int) int {
	// Try sysfs GPIO interface
	paths := []string{
		fmt.Sprintf("/sys/class/gpio/gpio%d/value", pin),
		fmt.Sprintf("/host/sys/class/gpio/gpio%d/value", pin),
	}

	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			val := strings.TrimSpace(string(data))
			if val == "1" {
				return 1
			}
			return 0
		}
	}

	// Try gpiod if available
	if output, err := runCommand("gpioget", "gpiochip0", fmt.Sprintf("%d", pin)); err == nil {
		if strings.TrimSpace(output) == "1" {
			return 1
		}
		return 0
	}

	// Try raspi-gpio
	if output, err := runCommand("raspi-gpio", "get", fmt.Sprintf("%d", pin)); err == nil {
		if strings.Contains(output, "level=1") {
			return 1
		}
		return 0
	}

	// Default: assume power good (GPIO not accessible)
	if pin == m.gpioPower {
		return 1 // Default to power good
	}
	return 0
}

// SetCharging enables or disables charging (GPIO16)
func (m *PowerManager) SetCharging(enable bool) error {
	value := "0"
	if enable {
		value = "1"
	}

	paths := []string{
		fmt.Sprintf("/sys/class/gpio/gpio%d/value", m.gpioCharge),
		fmt.Sprintf("/host/sys/class/gpio/gpio%d/value", m.gpioCharge),
	}

	for _, path := range paths {
		if err := os.WriteFile(path, []byte(value), 0644); err == nil {
			return nil
		}
	}

	// Try gpiod
	val := "0"
	if enable {
		val = "1"
	}
	_, err := runCommand("gpioset", "gpiochip0", fmt.Sprintf("%d=%s", m.gpioCharge, val))
	return err
}

// IsAvailable returns whether UPS hardware was detected
func (m *PowerManager) IsAvailable() bool {
	return m.available
}

// GetCachedStatus returns the last cached status without reading hardware
func (m *PowerManager) GetCachedStatus() *UPSStatus {
	m.statusLock.RLock()
	defer m.statusLock.RUnlock()

	if m.lastStatus == nil {
		return m.GetStatus()
	}
	return m.lastStatus
}

// Helper to run shell commands
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	return string(output), err
}
