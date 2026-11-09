package uplink

// Adapter is a read-only OS snapshot. ID is the stable Windows adapter GUID;
// Index and Addresses may change when the adapter reconnects.
type Adapter struct {
	Index     int      `json:"index"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
	Gateway   string   `json:"gateway"`
}
