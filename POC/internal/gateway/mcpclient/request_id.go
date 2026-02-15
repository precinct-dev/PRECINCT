package mcpclient

import "sync/atomic"

// wireRequestIDCounter provides monotonic JSON-RPC IDs for upstream wire requests.
// RFA-l6h6.7.3: prevents response correlation collisions when callers reuse IDs.
var wireRequestIDCounter uint64

func nextWireRequestID() int {
	return int(atomic.AddUint64(&wireRequestIDCounter, 1))
}
