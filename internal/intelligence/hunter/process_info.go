package hunter

// ProcessInfo holds diagnostic data about an inspected process.
type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	CmdLine string `json:"cmdline,omitempty"`
}
