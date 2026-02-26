package skeleton

// Adapter helpers to express OpenClaw-originated requests through the v2.4
// control-plane contracts without coupling OpenClaw internals to gateway types.

const defaultTenant = "tenant-a"

type EnvelopeParams struct {
	RunID     string
	SessionID string
	SPIFFEID  string
	Plane     string
}

type IngressSubmitParams struct {
	EnvelopeParams
	ConnectorID        string
	ConnectorSignature string
	SourceID           string
	SourcePrincipal    string
	EventID            string
	EventTimestamp     string
}

type ContextAdmitParams struct {
	EnvelopeParams
	Attributes map[string]any
}

type ModelCallParams struct {
	EnvelopeParams
	Attributes map[string]any
}

type ToolExecuteParams struct {
	EnvelopeParams
	Resource   string
	Attributes map[string]any
}

func envelopeForPlane(params EnvelopeParams) map[string]any {
	return map[string]any{
		"run_id":          params.RunID,
		"session_id":      params.SessionID,
		"tenant":          defaultTenant,
		"actor_spiffe_id": params.SPIFFEID,
		"plane":           params.Plane,
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func buildRequest(envelope EnvelopeParams, action, resource string, attributes map[string]any) map[string]any {
	rootEnv := envelopeForPlane(envelope)
	policyEnv := envelopeForPlane(envelope)
	return map[string]any{
		"envelope": rootEnv,
		"policy": map[string]any{
			"envelope":   policyEnv,
			"action":     action,
			"resource":   resource,
			"attributes": cloneMap(attributes),
		},
	}
}

func BuildIngressSubmitRequest(params IngressSubmitParams) map[string]any {
	return buildRequest(
		params.EnvelopeParams,
		"ingress.admit",
		"ingress/event",
		map[string]any{
			"connector_id":        params.ConnectorID,
			"connector_signature": params.ConnectorSignature,
			"source_id":           params.SourceID,
			"source_principal":    params.SourcePrincipal,
			"event_id":            params.EventID,
			"event_timestamp":     params.EventTimestamp,
		},
	)
}

func BuildContextMemoryRequest(params ContextAdmitParams) map[string]any {
	return buildRequest(
		params.EnvelopeParams,
		"context.admit",
		"context/segment",
		params.Attributes,
	)
}

func BuildModelCallRequest(params ModelCallParams) map[string]any {
	return buildRequest(
		params.EnvelopeParams,
		"model.call",
		"model/inference",
		params.Attributes,
	)
}

func BuildToolExecuteRequest(params ToolExecuteParams) map[string]any {
	resource := params.Resource
	if resource == "" {
		resource = "tool/read"
	}
	return buildRequest(
		params.EnvelopeParams,
		"tool.execute",
		resource,
		params.Attributes,
	)
}
