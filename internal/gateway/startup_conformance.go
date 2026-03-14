package gateway

import "log/slog"

func emitStartupConformanceReport(profile *enforcementProfileRuntime, extraControls []enforcementControlResult) {
	if profile == nil {
		return
	}

	controls := append([]enforcementControlResult(nil), profile.ControlResults...)
	controls = append(controls, extraControls...)

	status := "pass"
	for _, control := range controls {
		if control.Status == "fail" {
			status = "fail"
			break
		}
	}

	slog.Info("startup conformance report",
		"profile", profile.Name,
		"startup_gate_mode", profile.StartupGateMode,
		"status", status,
		"controls", controls,
	)
}
