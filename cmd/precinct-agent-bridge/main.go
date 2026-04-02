package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type config struct {
	ListenAddr               string
	UpstreamURL              string
	IdentityMode             string
	SPIFFEIDHeader           string
	SPIFFEEndpointSocket     string
	UpstreamAllowedSPIFFEIDs []string
	ModelAliases             map[string]string
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("bridge config: %v", err)
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("parse BRIDGE_UPSTREAM_URL: %v", err)
	}

	transport, shutdown, mode, err := buildTransport(cfg, upstream)
	if err != nil {
		log.Fatalf("bridge transport: %v", err)
	}
	if shutdown != nil {
		defer shutdown()
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = transport
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !isStreamingChatCompletionResponse(resp) {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		streamBody, err := synthesizeChatCompletionStream(body)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			return nil
		}
		resp.Body = io.NopCloser(bytes.NewReader(streamBody))
		resp.ContentLength = int64(len(streamBody))
		resp.Header.Set("Content-Type", "text/event-stream; charset=utf-8")
		resp.Header.Set("Cache-Control", "no-cache")
		resp.Header.Set("Connection", "keep-alive")
		resp.Header.Set("Content-Length", strconv.Itoa(len(streamBody)))
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("bridge proxy error: %v", err)
		http.Error(w, "upstream bridge error", http.StatusBadGateway)
	}
	proxy.Rewrite = func(req *httputil.ProxyRequest) {
		req.SetURL(upstream)
		req.SetXForwarded()
		req.Out.Host = upstream.Host
		req.Out.URL.Path = rewriteOpenAICompatPath(req.Out.URL.Path)
		if req.Out.URL.RawPath != "" {
			req.Out.URL.RawPath = rewriteOpenAICompatPath(req.Out.URL.RawPath)
		}
		if err := normalizeModelAlias(req.Out, cfg.ModelAliases); err != nil {
			log.Printf("bridge request normalization skipped: %v", err)
		}
		if mode == "header" && strings.TrimSpace(cfg.SPIFFEIDHeader) != "" {
			req.Out.Header.Set("X-SPIFFE-ID", cfg.SPIFFEIDHeader)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantsOpenAIChatCompletionStream(r) {
			r = r.WithContext(context.WithValue(r.Context(), streamRequestContextKey{}, true))
		}
		proxy.ServeHTTP(w, r)
	}))

	log.Printf("precinct-agent-bridge listening on %s -> %s (mode=%s)", cfg.ListenAddr, cfg.UpstreamURL, mode)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("bridge serve: %v", err)
	}
}

func loadConfig() (*config, error) {
	cfg := &config{
		ListenAddr:           firstNonEmpty(os.Getenv("BRIDGE_LISTEN_ADDR"), "127.0.0.1:9080"),
		UpstreamURL:          strings.TrimSpace(os.Getenv("BRIDGE_UPSTREAM_URL")),
		IdentityMode:         strings.ToLower(strings.TrimSpace(firstNonEmpty(os.Getenv("BRIDGE_IDENTITY_MODE"), "auto"))),
		SPIFFEIDHeader:       strings.TrimSpace(os.Getenv("BRIDGE_SPIFFE_ID_HEADER")),
		SPIFFEEndpointSocket: strings.TrimSpace(firstNonEmpty(os.Getenv("SPIFFE_ENDPOINT_SOCKET"), "unix:///run/spire/sockets/agent.sock")),
	}
	for _, raw := range strings.Split(os.Getenv("BRIDGE_UPSTREAM_ALLOWED_SPIFFE_IDS"), ",") {
		if id := strings.TrimSpace(raw); id != "" {
			cfg.UpstreamAllowedSPIFFEIDs = append(cfg.UpstreamAllowedSPIFFEIDs, id)
		}
	}
	cfg.ModelAliases = loadModelAliases(os.Getenv("BRIDGE_MODEL_ALIAS_MAP"))
	if cfg.UpstreamURL == "" {
		return nil, errors.New("BRIDGE_UPSTREAM_URL is required")
	}
	switch cfg.IdentityMode {
	case "auto", "header", "mtls", "none":
	default:
		return nil, errors.New("BRIDGE_IDENTITY_MODE must be one of auto, header, mtls, none")
	}
	return cfg, nil
}

func buildTransport(cfg *config, upstream *url.URL) (http.RoundTripper, func(), string, error) {
	mode := cfg.IdentityMode
	if mode == "auto" {
		switch strings.ToLower(upstream.Scheme) {
		case "https":
			mode = "mtls"
		default:
			if cfg.SPIFFEIDHeader != "" {
				mode = "header"
			} else {
				mode = "none"
			}
		}
	}

	switch mode {
	case "mtls":
		ctx, cancel := context.WithCancel(context.Background())
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.SPIFFEEndpointSocket)))
		if err != nil {
			cancel()
			return nil, nil, "", err
		}
		authorizer := tlsconfig.AuthorizeAny()
		if len(cfg.UpstreamAllowedSPIFFEIDs) > 0 {
			ids := make([]spiffeid.ID, 0, len(cfg.UpstreamAllowedSPIFFEIDs))
			for _, raw := range cfg.UpstreamAllowedSPIFFEIDs {
				id, err := spiffeid.FromString(raw)
				if err != nil {
					closeX509Source(source)
					cancel()
					return nil, nil, "", err
				}
				ids = append(ids, id)
			}
			authorizer = tlsconfig.AuthorizeOneOf(ids...)
		}
		tlsCfg := tlsconfig.MTLSClientConfig(source, source, authorizer)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsCfg
		return transport, func() {
			closeX509Source(source)
			cancel()
		}, mode, nil
	case "header", "none":
		return http.DefaultTransport.(*http.Transport).Clone(), nil, mode, nil
	default:
		return nil, nil, "", errors.New("unsupported bridge mode")
	}
}

func closeX509Source(source *workloadapi.X509Source) {
	if source == nil {
		return
	}
	if err := source.Close(); err != nil {
		log.Printf("bridge source close error: %v", err)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type streamRequestContextKey struct{}

func rewriteOpenAICompatPath(path string) string {
	switch path {
	case "/v1/chat/completions", "/v1/responses", "/v1/models", "/v1/embeddings":
		return "/openai" + path
	default:
		return path
	}
}

type openAIChatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type openAIChatCompletionChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func wantsOpenAIChatCompletionStream(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return false
	}
	if req.Method != http.MethodPost {
		return false
	}
	switch req.URL.Path {
	case "/v1/chat/completions", "/openai/v1/chat/completions":
	default:
		return false
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
		req.ContentLength = 0
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		return false
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	if len(body) == 0 {
		return false
	}
	var payload struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Stream
}

func isStreamingChatCompletionResponse(resp *http.Response) bool {
	if resp == nil || resp.Request == nil {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if streamRequested, _ := resp.Request.Context().Value(streamRequestContextKey{}).(bool); !streamRequested {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return false
	}
	switch resp.Request.URL.Path {
	case "/openai/v1/chat/completions", "/v1/chat/completions":
		return true
	default:
		return false
	}
}

func synthesizeChatCompletionStream(body []byte) ([]byte, error) {
	var completion openAIChatCompletionResponse
	if err := json.Unmarshal(body, &completion); err != nil {
		return nil, err
	}
	if completion.Object != "chat.completion" || len(completion.Choices) == 0 {
		return nil, fmt.Errorf("unsupported completion object %q", completion.Object)
	}
	choice := completion.Choices[0]
	if strings.TrimSpace(choice.Message.Content) == "" && strings.TrimSpace(choice.FinishReason) == "" {
		return nil, errors.New("completion body missing content and finish reason")
	}

	firstChunk := openAIChatCompletionChunk{
		ID:      completion.ID,
		Object:  "chat.completion.chunk",
		Created: completion.Created,
		Model:   completion.Model,
	}
	firstChunk.Choices = append(firstChunk.Choices, struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	}{
		Index: choice.Index,
		Delta: struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		}{
			Role:    firstNonEmpty(choice.Message.Role, "assistant"),
			Content: choice.Message.Content,
		},
	})

	finishReason := firstNonEmpty(choice.FinishReason, "stop")
	finalChunk := openAIChatCompletionChunk{
		ID:      completion.ID,
		Object:  "chat.completion.chunk",
		Created: completion.Created,
		Model:   completion.Model,
	}
	finalChunk.Choices = append(finalChunk.Choices, struct {
		Index int `json:"index"`
		Delta struct {
			Role    string `json:"role,omitempty"`
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	}{
		Index:        choice.Index,
		FinishReason: &finishReason,
	})

	firstJSON, err := json.Marshal(firstChunk)
	if err != nil {
		return nil, err
	}
	finalJSON, err := json.Marshal(finalChunk)
	if err != nil {
		return nil, err
	}

	var stream bytes.Buffer
	stream.WriteString("data: ")
	stream.Write(firstJSON)
	stream.WriteString("\n\n")
	stream.WriteString("data: ")
	stream.Write(finalJSON)
	stream.WriteString("\n\n")
	stream.WriteString("data: [DONE]\n\n")
	return stream.Bytes(), nil
}

func loadModelAliases(raw string) map[string]string {
	aliases := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		from := strings.TrimSpace(parts[0])
		to := strings.TrimSpace(parts[1])
		if from == "" || to == "" {
			continue
		}
		aliases[from] = to
	}
	return aliases
}

func normalizeModelAlias(req *http.Request, aliases map[string]string) error {
	if req == nil || req.Body == nil || len(aliases) == 0 {
		return nil
	}
	if req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodPatch {
		return nil
	}
	if req.URL == nil {
		return nil
	}
	switch req.URL.Path {
	case "/openai/v1/chat/completions", "/openai/v1/responses", "/v1/chat/completions", "/v1/responses":
	default:
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	_ = req.Body.Close()
	if len(body) == 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	normalized, changed, err := rewriteModelAlias(body, aliases)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		return err
	}
	if !changed {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		return nil
	}

	req.Body = io.NopCloser(bytes.NewReader(normalized))
	req.ContentLength = int64(len(normalized))
	req.Header.Set("Content-Length", strconv.Itoa(len(normalized)))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(normalized)), nil
	}
	return nil
}

func rewriteModelAlias(body []byte, aliases map[string]string) ([]byte, bool, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false, err
	}

	model, _ := payload["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" {
		return body, false, nil
	}

	canonical, ok := aliases[model]
	if !ok || canonical == model {
		return body, false, nil
	}

	payload["model"] = canonical
	normalized, err := json.Marshal(payload)
	if err != nil {
		return nil, false, err
	}
	log.Printf("bridge normalized model alias %q -> %q", model, canonical)
	return normalized, true, nil
}
