# Axiom: Go-Native Agentic AI Assistant Platform

## Context

We studied four AI assistant platforms and identified what each does well:

| Platform | Language | Strength | Weakness |
|----------|----------|----------|----------|
| **Platform A** | TypeScript | Channel breadth (15+ integrations), plugin ecosystem | No tool sandboxing, LLM has raw credential access |
| **Platform B** | Rust | Security model (WASM sandboxing, credential injection, leak detection) | Complexity, ecosystem coupling |
| **Platform C** | Go | Simplicity (message bus, thin orchestration, <10MB) | No database, no graph, minimal security |
| **Nanobot** | Python | Minimalism (4K LOC, LiteLLM leverage, fast to understand) | No sandboxing, single-threaded, fragile at scale |

Rather than forking any of these, Axiom is a new platform built native to our existing ecosystem:

- **PRECINCT** (Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools) (Go, 13-layer middleware gateway with SPIFFE/SPIKE/OPA/KeyDB/OTel)
- **Beads** (Go, distributed git-backed issue tracker with Go library API and swarm primitives)
- **RLM** (Python, Recursive Language Models for near-infinite context via recursive self-calls)
- **RustReason** (Rust + PyO3, high-performance temporal graph reasoning -- our PyReason port)
- **SynaReason** (Python/Rust, neuro-symbolic extraction + formal reasoning + proof trees)
- **Apache AGE** (Go driver available, Cypher on PostgreSQL) + **SurrealDB** (graph+document+vector native)
- **KeyDB** (already in reference architecture for sessions/rate limiting)
- **Obsidian** (CLI-accessible knowledge vault for human-readable knowledge mirror)

### Why "Axiom"

An axiom is a self-evident truth that needs no external proof. This reflects the core philosophy: answers are grounded in formal reasoning and symbolic verification, not hallucinated. When Axiom uses RustReason to produce a proof tree, that proof IS the answer -- axiomatic, verifiable, auditable.

Alternative names if Axiom is taken: **Forge** (hardened, enterprise), **Praxis** (theory into practice).

---

## Architecture Overview

```
                    Channels (Telegram, Discord, Slack, WhatsApp, Signal, Teams, ...)
                              |
                    [Redis Streams via KeyDB]
                              |
                    Dispatcher (creates beads, routes responses)
                              |
                +-------------+-------------+
                |                           |
          Cattle Agents               Pet Agents
          (stateless pool)      (curator, sentinel, timekeeper,
                |                librarian, scheduler)
                |                           |
          [RLM Agent Loop]           [Specialized Loops]
                |
     +----------+----------+
     |          |          |
  RLM       RustReason  SynaReason
  (gRPC)    (gRPC)      (gRPC)
     |
  [Tool calls through Security Gateway (13-layer)]
     |
  [Knowledge Graph: AGE (enterprise) / SurrealDB (personal)]
     |
  [Beads: System of Record for all activities]
```

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Go (main runtime), Python/Rust gRPC sidecars | Consistency with reference architecture and beads; Go for concurrency and single-binary distribution |
| Agent loop | RLM-based (NOT ReAct) | Recursive decomposition enables multi-level reasoning; sub-LM calls allow different models per subtask |
| Message bus | Redis Streams via KeyDB | Already in the stack (zero new dependencies), supports consumer groups for competing consumers |
| Graph DB (enterprise) | Apache AGE (PostgreSQL) | Go driver exists in workspace, Cypher query language, fits the PostgreSQL ecosystem, pgvector for embeddings |
| Graph DB (personal) | SurrealDB | Graph+document+vector native in one binary, minimal ops burden for personal use |
| Polyglot boundary | gRPC services | Clean contracts via protobuf, independent scaling, language-agnostic, streaming support |
| Work coordination | Beads as System of Record | Go library API (`beads.Open()`, `GetReadyWork()`), distributed via git, dependency-aware, swarm primitives built in |
| Security | Inherit the 13-layer gateway | Proven, already built, enterprise-compliant (SOC 2, ISO 27001, GDPR), not reinventing |
| Deployment | Docker Compose (personal) / K8s (enterprise) | Reference architecture already has both patterns with overlays |
| Observability | OpenTelemetry (inherited) | Per-middleware spans, audit journals, OTLP export -- already proven in reference architecture |

---

## Repository Structure

```
axiom/
  go.mod                          # github.com/<org>/axiom
  go.sum
  Makefile
  CLAUDE.md
  .beads/
  .golangci.yml

  cmd/
    axiom/                        # Main daemon (agent loop, bus, channels)
      main.go
    axctl/                        # CLI tool (status, config, channel management)
      main.go
      cmd_status.go
      cmd_agent.go
      cmd_channel.go
      cmd_graph.go

  pkg/                            # Public interfaces (importable by extensions)
    channel/
      channel.go                  # Channel interface + message types
      message.go                  # InboundMessage, OutboundMessage, Attachment
    graph/
      graph.go                    # GraphStore interface
      types.go                    # Node, Edge, NodeID, EdgeID, filters
    agent/
      agent.go                    # Agent interface (cattle/pet)
      types.go                    # AgentKind, HealthStatus, State
    reasoner/
      reasoner.go                 # Reasoner interface (unified gRPC client)
      types.go                    # Request/response types for all sidecars
    bus/
      bus.go                      # Bus interface
      message.go                  # Message envelope, PendingMessage

  internal/
    channels/                     # Channel implementations
      manager.go                  # ChannelManager: multiplexes all channels
      telegram/telegram.go
      discord/discord.go
      slack/slack.go
      whatsapp/whatsapp.go        # Via Node.js bridge (ported from prior reference implementations)
      signal/signal.go
      teams/teams.go
      webchat/webchat.go          # HTTP/SSE for browser UI
      webhook/webhook.go          # Generic webhook (catch-all)

    graphstore/                   # Graph backends
      age/                        # Apache AGE (enterprise)
        age.go                    # GraphStore implementation
        cypher.go                 # Cypher query builder
        age_test.go
      surreal/                    # SurrealDB (personal)
        surreal.go                # GraphStore implementation
        surql.go                  # SurrealQL query builder
        surreal_test.go
      memory/                     # In-memory (testing)
        memory.go

    bus/
      keydb/                      # Redis Streams via KeyDB
        streams.go                # Bus implementation using XADD/XREADGROUP/XACK
        streams_test.go
      memory/                     # In-memory (testing)
        memory.go

    loop/                         # RLM-based agent loop
      loop.go                     # Core recursive loop orchestrator
      decompose.go                # Task decomposition into sub-tasks
      reflect.go                  # Quality check against acceptance criteria
      loop_test.go

    swarm/
      dispatcher.go               # Channel -> bead -> agent -> response routing
      registry.go                 # Pet agent registry + lifecycle management
      heartbeat.go                # Liveness monitoring for all agents

    pets/                         # Maintenance agents (pets)
      curator.go                  # Knowledge graph: dedup, linking, consolidation
      sentinel.go                 # Security: anomaly detection, PII scanning
      librarian.go                # Documents: indexing, context selection, citations
      timekeeper.go               # Temporal: TTL enforcement, confidence decay, liveness
      scheduler.go                # Cron: recurring task evaluation, backfill

    grpc/                         # gRPC clients to sidecars
      rlm/client.go               # RLM sidecar client
      rustreason/client.go        # RustReason sidecar client
      synareason/client.go        # SynaReason sidecar client

    security/
      gateway.go                  # Wraps tool calls through the 13-layer security gateway
      gateway_test.go

    config/
      config.go                   # Configuration loading (env vars, files, defaults)
      config_test.go

  proto/                          # Protobuf definitions
    rlm/v1/rlm.proto
    rustreason/v1/rustreason.proto
    synareason/v1/synareason.proto
    bus/v1/events.proto           # Shared event envelope

  services/                       # Sidecar service implementations
    rlm-sidecar/                  # Python gRPC server wrapping rlm.RLM().completion()
      server.py
      requirements.txt
      Dockerfile
    rustreason-sidecar/           # Rust gRPC server wrapping ReasoningEngine
      src/main.rs
      Cargo.toml
      Dockerfile
    synareason-sidecar/           # Python gRPC server wrapping synareason.Session
      server.py
      requirements.txt
      Dockerfile

  docker/
    Dockerfile.axiom              # Main Go daemon
    Dockerfile.rlm-sidecar
    Dockerfile.rustreason-sidecar
    Dockerfile.synareason-sidecar

  docker-compose.yml              # Personal deployment (SurrealDB)
  docker-compose.enterprise.yml   # Enterprise overlay (AGE + security stack)

  infra/k8s/
    base/                         # Core services (axiom, keydb, sidecars)
      namespace.yaml
      axiom-deployment.yaml
      keydb-statefulset.yaml
      rlm-sidecar-deployment.yaml
      rustreason-sidecar-deployment.yaml
      synareason-sidecar-deployment.yaml
      configmap.yaml
    overlays/
      personal/                   # SurrealDB variant
        kustomization.yaml
        surreal-statefulset.yaml
      enterprise/                 # AGE + full security stack
        kustomization.yaml
        age-statefulset.yaml
        gateway-deployment.yaml
        spire-daemonset.yaml

  config/
    opa/                          # OPA policies (ported from reference architecture)
      agent_tool_policy.rego
    tool-registry.yaml            # MCP tool definitions with SHA-256 hashes
    channels.yaml                 # Channel configuration

  tests/
    integration/
      agent_loop_test.go
      swarm_coordination_test.go
      bus_keydb_test.go
      graph_age_test.go
      graph_surreal_test.go
    e2e/
      full_flow_test.go
      channel_telegram_test.go
```

---

## Core Interfaces

### Channel

```go
// pkg/channel/channel.go
package channel

import "context"

// Channel is the interface all messaging platform adapters implement.
// Inspired by PicoClaw's simplicity: receive messages, send responses.
type Channel interface {
    // Name returns the channel identifier (e.g., "telegram", "slack").
    Name() string

    // Start begins listening for incoming messages. Blocks until ctx is cancelled.
    // Received messages are delivered to the handler.
    Start(ctx context.Context, handler MessageHandler) error

    // Send delivers a message to a specific conversation.
    Send(ctx context.Context, msg OutboundMessage) error

    // Close shuts down the channel gracefully.
    Close() error
}

// MessageHandler processes an incoming message from any channel.
type MessageHandler func(ctx context.Context, msg InboundMessage) error

// InboundMessage represents a message received from a channel.
type InboundMessage struct {
    ID             string            // Channel-specific message ID
    ChannelName    string            // Which channel this came from
    ConversationID string            // Thread/chat/DM identifier
    SenderID       string            // User identifier within the channel
    SenderName     string            // Human-readable sender name
    Text           string            // Message text content
    Attachments    []Attachment      // Files, images, voice notes
    Metadata       map[string]string // Channel-specific metadata
    Timestamp      int64             // Unix milliseconds
}

// OutboundMessage represents a message to send via a channel.
type OutboundMessage struct {
    ConversationID string            // Where to send
    Text           string            // Message text (markdown supported)
    ReplyToID      string            // Optional: reply to a specific message
    Attachments    []Attachment      // Optional files
    Metadata       map[string]string // Channel-specific send options
}

// Attachment represents a file or media attachment.
type Attachment struct {
    Filename string
    MimeType string
    Data     []byte // For small attachments (inline)
    URL      string // For large attachments (presigned URL or reference)
}
```

### GraphStore

```go
// pkg/graph/graph.go
package graph

import (
    "context"
    "time"
)

// GraphStore provides an abstraction over graph database backends.
// Enterprise: Apache AGE (PostgreSQL + Cypher)
// Personal: SurrealDB (SurrealQL)
type GraphStore interface {
    // --- Node Operations ---
    CreateNode(ctx context.Context, label string, props map[string]any) (NodeID, error)
    GetNode(ctx context.Context, id NodeID) (*Node, error)
    UpdateNode(ctx context.Context, id NodeID, props map[string]any) error
    DeleteNode(ctx context.Context, id NodeID) error

    // --- Edge Operations ---
    CreateEdge(ctx context.Context, from, to NodeID, label string, props map[string]any) (EdgeID, error)
    GetEdges(ctx context.Context, filter EdgeFilter) ([]*Edge, error)
    DeleteEdge(ctx context.Context, id EdgeID) error

    // --- Traversal ---
    Neighbors(ctx context.Context, id NodeID, filter NeighborFilter) ([]*Node, error)
    ShortestPath(ctx context.Context, from, to NodeID, maxDepth int) ([]*Node, error)

    // --- Raw Query (backend-specific: Cypher for AGE, SurrealQL for SurrealDB) ---
    Query(ctx context.Context, query string, params map[string]any) (QueryResult, error)

    // --- Maintenance (used by pet agents) ---
    DecayConfidence(ctx context.Context, threshold float64, olderThan time.Time) (int, error)
    FindDuplicates(ctx context.Context, similarity float64) ([][]*Node, error)
    FactsAt(ctx context.Context, nodeID NodeID, at time.Time) ([]*Edge, error)

    // --- Lifecycle ---
    Close() error
    Ping(ctx context.Context) error
}

type NodeID string
type EdgeID string

type Node struct {
    ID         NodeID
    Label      string
    Properties map[string]any
    CreatedAt  time.Time
    UpdatedAt  time.Time
}

type Edge struct {
    ID         EdgeID
    From       NodeID
    To         NodeID
    Label      string
    Properties map[string]any // Includes valid_from, valid_to, confidence
    CreatedAt  time.Time
}

type Direction int

const (
    Outbound Direction = iota
    Inbound
    Both
)

type EdgeFilter struct {
    FromNode *NodeID
    ToNode   *NodeID
    Label    string
}

type NeighborFilter struct {
    Direction Direction
    EdgeLabel string // Empty = any
    NodeLabel string // Empty = any
    MaxDepth  int    // 1 = direct neighbors
}

type QueryResult struct {
    Nodes []*Node
    Edges []*Edge
    Raw   []map[string]any // Backend-specific raw results
}
```

### Agent

```go
// pkg/agent/agent.go
package agent

import (
    "context"
    "time"
)

// Agent is the interface all agents implement (both cattle and pet).
type Agent interface {
    // ID returns the agent's unique identifier.
    // Cattle: generated at spawn time (ephemeral UUID).
    // Pet: stable, configured at startup (e.g., "curator", "sentinel").
    ID() string

    // Kind returns whether this is a Cattle or Pet agent.
    Kind() AgentKind

    // Run starts the agent's main loop. Blocks until ctx is cancelled.
    Run(ctx context.Context) error

    // Heartbeat returns the agent's current health status.
    Heartbeat() HealthStatus

    // Stop gracefully shuts down the agent.
    Stop(ctx context.Context) error
}

type AgentKind int

const (
    Cattle AgentKind = iota // Identical, stateless, horizontally scalable
    Pet                      // Named, stateful, specific maintenance role
)

type State string

const (
    StateIdle     State = "idle"
    StateRunning  State = "running"
    StateWorking  State = "working"
    StateStuck    State = "stuck"
    StateStopped  State = "stopped"
    StateDead     State = "dead"
)

type HealthStatus struct {
    State      State
    LastActive time.Time
    CurrentJob string // Bead ID if working, empty if idle
    Error      string // Non-empty if stuck
}
```

### Bus

```go
// pkg/bus/bus.go
package bus

import (
    "context"
    "time"
)

// Bus abstracts the message bus. Implementation: Redis Streams via KeyDB.
type Bus interface {
    // Publish sends a message to a stream.
    Publish(ctx context.Context, stream string, msg *Message) error

    // Subscribe creates a consumer in a consumer group and processes messages.
    // handler is called for each message. Blocks until ctx is cancelled.
    Subscribe(ctx context.Context, stream, group, consumer string, handler MessageHandler) error

    // Ack acknowledges a message as processed.
    Ack(ctx context.Context, stream, group, msgID string) error

    // Pending returns messages that have been delivered but not acknowledged.
    Pending(ctx context.Context, stream, group string, count int64) ([]*PendingMessage, error)

    // CreateGroup ensures a consumer group exists for a stream.
    CreateGroup(ctx context.Context, stream, group string) error

    // Close shuts down the bus connection.
    Close() error
}

type MessageHandler func(ctx context.Context, msg *Message) error

// Message is the envelope for all bus communication.
type Message struct {
    ID        string            // Stream entry ID (set by Redis on publish)
    Stream    string            // Which stream this was published to
    Type      string            // Event type (e.g., "channel.message", "agent.completed")
    Source    string            // Producer identity (agent ID, channel name)
    Payload   []byte            // JSON-encoded event-specific data
    Timestamp time.Time
    TraceID   string            // OpenTelemetry trace ID for distributed tracing
}

type PendingMessage struct {
    Message
    Consumer    string
    DeliveredAt time.Time
    Deliveries  int64
}
```

### Reasoner

```go
// pkg/reasoner/reasoner.go
package reasoner

import "context"

// Reasoner provides a unified interface to polyglot reasoning sidecars.
// Each method maps to a gRPC service call to a specific sidecar.
type Reasoner interface {
    // RLMCompletion invokes the RLM sidecar for recursive LLM completion.
    RLMCompletion(ctx context.Context, req *RLMRequest) (*RLMResponse, error)

    // TemporalReason invokes the RustReason sidecar for fixed-point graph reasoning.
    TemporalReason(ctx context.Context, req *TemporalReasonRequest) (*TemporalReasonResponse, error)

    // NeuroSymbolicExtract invokes the SynaReason sidecar for LLM extraction + formal reasoning.
    NeuroSymbolicExtract(ctx context.Context, req *NeuroSymbolicRequest) (*NeuroSymbolicResponse, error)

    // Close shuts down all gRPC connections.
    Close() error
}

type RLMRequest struct {
    Prompt       string
    RootPrompt   string // Optional: visible to root LM only
    MaxDepth     int    // Recursive depth (default 1)
    MaxIter      int    // Max iterations per depth (default 30)
    Backend      string // LLM backend (openai, anthropic, etc.)
    Model        string // Model name
    SystemPrompt string // Optional custom system prompt
    Metadata     map[string]string
}

type RLMResponse struct {
    Response      string
    Iterations    int
    ExecutionTime float64 // Seconds
    InputTokens   int64
    OutputTokens  int64
}

type TemporalReasonRequest struct {
    GraphML string   // GraphML-encoded knowledge graph
    Rules   []string // Rules in RustReason text format
    Facts   []string // Initial facts
    MaxTime int      // Max reasoning timesteps
}

type TemporalReasonResponse struct {
    Timesteps int
    Converged bool
    Nodes     map[string]map[string]string // node -> predicate -> interval
    ProofTrace string                      // Human-readable reasoning trace
}

type NeuroSymbolicRequest struct {
    Text              string   // Natural language input
    ExistingGraphJSON string   // Existing knowledge graph context
    Rules             []string // Existing reasoning rules
    Backend           string   // LLM backend for extraction
    Model             string
}

type NeuroSymbolicResponse struct {
    Entities      []ExtractedEntity
    Relationships []ExtractedRelationship
    NewRules      []string
    ProofTree     string // Formatted proof tree for audit
    Consistent    bool   // Whether new knowledge is consistent with existing graph
}

type ExtractedEntity struct {
    Name       string
    Type       string
    Properties map[string]string
    Confidence float64
}

type ExtractedRelationship struct {
    Source     string
    Target    string
    Type      string
    Confidence float64
}
```

---

## Agent Loop: RLM-Based (Not ReAct)

### Why Not ReAct

ReAct is a flat observe-think-act cycle:

```
Observe -> Think -> Act -> Observe -> Think -> Act -> ... -> Answer
```

Every iteration operates at the same level. The LLM decides which tool to call at each step. This is shallow -- it cannot recursively decompose a complex problem into sub-problems that require different reasoning strategies.

### RLM-Based Loop

RLM (Recursive Language Models) supports recursive decomposition:

```
Depth 0: Receive task -> LLM generates code/sub-tasks -> Execute in REPL
         -> Code spawns sub-RLM call at depth 1:
             Depth 1: Sub-task -> Different LLM at depth 1 -> Execute -> Return to depth 0
         -> LLM at depth 0 sees sub-results -> Synthesize final answer
```

### Concrete Agent Loop Flow

```
1. RECEIVE:    Cattle pulls work from beads (GetReadyWork)
2. CLAIM:      Atomic ClaimWork (prevents double-claiming across cattle pool)
3. CONTEXT:    Load relevant subgraph from GraphStore (Neighbors with depth)
4. DECOMPOSE:  Send task + context to RLM sidecar via gRPC
               - RLM depth 0: Root LLM analyzes the task
               - If complex: RLM generates code spawning sub-calls at depth 1+
               - Sub-calls can invoke:
                 (a) Another RLM completion (recursive decomposition)
                 (b) RustReason (formal temporal reasoning with proof trees)
                 (c) SynaReason (knowledge extraction + formal verification)
                 (d) Tool calls (routed through 13-layer security gateway)
               - Each sub-result feeds back into the parent RLM iteration
5. REFLECT:    Quality check against bead acceptance criteria (max 3 attempts)
               - If quality insufficient, loop back to step 4 with feedback
6. RECORD:     Store new knowledge in graph (entities, relationships, rules)
               Reasoning traces -> audit log
7. COMPLETE:   beads.CloseIssue() with result summary
8. NOTIFY:     Publish to bus "agent.events" stream
9. LOOP:       Back to step 1 (pull next work item)
```

### High-Stakes Decision Routing

When a task requires formal verification (detected via confidence threshold, bead metadata `high_stakes: true`, or domain rules in OPA):

1. Route to **RustReason** for temporal graph reasoning:
   - Extract relevant subgraph from knowledge graph
   - Apply domain rules (intervals, temporal constraints)
   - Produce proof tree with fixed-point convergence
2. Route to **SynaReason** for neuro-symbolic verification:
   - LLM extracts claims from the proposed answer
   - Claims are formally verified against the knowledge graph
   - Conflicts detected and reported
3. Proof tree recorded in **audit journal** (non-repudiable evidence)
4. If verification fails, the answer is rejected and the task re-enters the RLM loop

### Key Differences from ReAct

| Aspect | ReAct | RLM-Based |
|--------|-------|-----------|
| Depth | Flat (single level) | Recursive (configurable depth) |
| Tool selection | LLM picks one tool per step | Code generation spawns multiple sub-tasks |
| Model per step | Same model throughout | Different models per depth level |
| Error recovery | Retry the same step | Recursive error recovery with sub-calls |
| Composability | Monolithic | Sub-tasks use different reasoners (RLM, RustReason, SynaReason) |
| Formal verification | None | RustReason proof trees, SynaReason consistency checks |
| Knowledge integration | Context window only | Graph queries + temporal reasoning + extraction |

---

## Swarm Model

### Cattle (Stateless Workers)

Cattle agents are identical, interchangeable workers running the same loop:

```go
func (c *CattleAgent) Run(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
            items, err := c.beads.GetReadyWork(ctx, WorkFilter{
                MolType:  "work",
                WorkType: "mutex",     // One worker per task
                Limit:    1,
            })
            if err != nil || len(items) == 0 {
                time.Sleep(c.pollInterval)
                continue
            }
            if err := c.beads.ClaimWork(ctx, items[0].ID, c.ID()); err != nil {
                continue // Another agent claimed it -- normal contention
            }
            c.execute(ctx, items[0])
        }
    }
}
```

Scaling: Add more cattle replicas. They compete for work via atomic `ClaimWork` (beads sets status + assignee atomically). Losers simply poll again.

### Pets (Named, Stateful)

Each pet has a unique role and runs its own specialized loop:

| Pet | Role | What It Does | Trigger | Schedule |
|-----|------|-------------|---------|----------|
| **Curator** | Knowledge quality | Dedup nodes, improve edge linking, consolidate facts, manage confidence scores | Bus: `knowledge.mutations` | Every 6h patrol |
| **Sentinel** | Security monitoring | Anomaly detection in agent behavior, PII scanning in graph, security event audit | Bus: `agent.events`, `security.audit` | Continuous |
| **Librarian** | Document management | Index new documents, build summaries, select context for agents, track citations | Bus: `document.new` | Daily full reindex |
| **Timekeeper** | Temporal enforcement | TTL enforcement on ephemeral beads, confidence decay on old facts, agent liveness checks, deferred work activation | Scheduled | Every 15min |
| **Scheduler** | Recurring tasks | Evaluate cron expressions, create beads for triggered schedules, detect missed runs, backfill | Scheduled | Every 1min |

Pets do NOT pull from the general ready queue. They either:
1. React to bus events (sentinel, curator)
2. Run on a schedule (timekeeper, scheduler)
3. Patrol periodically (librarian)

Beads tracks pet state via `AgentState` and `last_activity`. If `last_activity` exceeds a threshold, the Timekeeper marks the pet as `dead` and creates a recovery bead.

### Coordination Protocol

```
1. Human sends message via channel (e.g., Telegram)
2. Channel adapter publishes to bus: stream "channel.inbound"
3. Dispatcher reads from "channel.inbound", creates a bead:
   - issue_type: "task"
   - priority: auto-classified
   - metadata: { channel, conversation_id, sender }
4. Cattle agents poll GetReadyWork, one claims the bead
5. Agent executes via RLM loop
6. On completion, agent publishes to bus: stream "agent.events"
7. Dispatcher reads "agent.events", routes response back via channel adapter
8. Bead is closed with result summary
```

### Swarm Molecules

For complex tasks requiring coordinated multi-agent work, beads supports molecules (`MolType: "swarm"`):

1. Dispatcher decomposes the task into sub-beads with `parent-child` dependencies
2. Multiple cattle agents work on sub-beads in parallel
3. Parent bead tracks completion of children
4. Final synthesis agent assembles results from all children

---

## Redis Streams Topology

### Stream Names and Consumer Groups

```
channel.inbound              # All channel messages
  -> Consumer Group: "dispatchers"   (create beads, route to agents)

agent.events                 # Agent lifecycle: claimed, completed, failed, stuck
  -> Consumer Group: "dispatchers"   (route responses back to channels)
  -> Consumer Group: "sentinels"     (anomaly monitoring)

knowledge.mutations          # Graph changes: new entities, edges, updates
  -> Consumer Group: "curators"      (quality maintenance)
  -> Consumer Group: "sentinels"     (data validation)

system.heartbeats            # Agent liveness pings
  -> Consumer Group: "timekeepers"   (liveness monitoring)

system.schedules             # Schedule trigger events
  -> Consumer Group: "schedulers"    (cron evaluation)

security.audit               # Security-relevant events
  -> Consumer Group: "sentinels"     (security monitoring)
```

### Message Envelope

All messages use a common envelope (defined in `proto/bus/v1/events.proto`):

```protobuf
message Envelope {
  string id = 1;                    // Unique message ID
  string type = 2;                  // Event type (e.g., "channel.message")
  string source = 3;                // Producer identity
  google.protobuf.Timestamp ts = 4;
  string trace_id = 5;              // OTel trace ID
  bytes payload = 6;                // Type-specific payload
  map<string, string> metadata = 7;
}
```

---

## Knowledge Graph Schema

### Node Labels

```
Person          { name, email, platform, org }
Agent           { agent_id, kind, role, state, last_active }
Concept         { name, domain, description, confidence }
Entity          { name, type, source, extracted_at }
Conversation    { channel, started_at, topic, bead_id }
Task            { bead_id, title, status, priority }
Document        { title, url, content_hash, indexed_at }
Rule            { name, body, domain, created_by, proof_hash }
Event           { type, timestamp, source, severity }
Preference      { key, value, scope }
Schedule        { cron_expr, name, next_run, last_run }
Channel         { name, type, config_hash }
```

### Edge Labels

```
# Knowledge edges
KNOWS_ABOUT      Person -> Concept       { confidence, since }
RELATED_TO       Concept -> Concept      { strength, type }
EXTRACTED_FROM   Entity -> Document      { confidence, method }
MENTIONS         Document -> Entity      { count, positions }
DERIVED_BY       Rule -> Entity          { proof_hash }

# Conversation edges
SENT_BY          Conversation -> Person  { timestamp }
ABOUT            Conversation -> Concept { relevance }
PRODUCED         Conversation -> Task    { timestamp }

# Agent edges
WORKED_ON        Agent -> Task           { started_at, completed_at, quality_score }
LEARNED          Agent -> Concept        { timestamp, source_task }
SPECIALIZES_IN   Agent -> Concept        { proficiency }

# Temporal reasoning edges (RustReason-compatible)
CAUSES           Event -> Event          { delay, probability }
PRECEDES         Entity -> Entity        { temporal_interval }
CONTRADICTS      Rule -> Rule            { explanation }

# Preference edges
PREFERS          Person -> Preference    { since, confidence }
DISLIKES         Person -> Preference    { since, confidence }
```

### Temporal Properties

All edges carry:
- `valid_from` / `valid_to`: temporal interval (compatible with RustReason's `Interval` type)
- `confidence`: float64 [0,1] (subject to time decay by Timekeeper pet)
- `source`: provenance tracking (which agent/conversation/extraction created this)

This enables:
- Temporal queries: "What did the system know as of date X?"
- Confidence decay: Old facts lose confidence unless reinforced
- RustReason formal reasoning over the knowledge graph's temporal dimension
- Provenance chains: Any fact can be traced back to its source

---

## gRPC Service Contracts

### RLM Sidecar (proto/rlm/v1/rlm.proto)

```protobuf
syntax = "proto3";
package rlm.v1;

service RLMService {
  rpc Completion(CompletionRequest) returns (CompletionResponse);
  rpc StreamCompletion(CompletionRequest) returns (stream IterationResult);
  rpc Health(HealthRequest) returns (HealthResponse);
}

message CompletionRequest {
  string prompt = 1;
  string root_prompt = 2;
  int32 max_depth = 3;
  int32 max_iterations = 4;
  string backend = 5;
  string model = 6;
  string system_prompt = 7;
  map<string, string> metadata = 8;
}

message CompletionResponse {
  string response = 1;
  int32 iterations_used = 2;
  double execution_time = 3;
  int64 input_tokens = 4;
  int64 output_tokens = 5;
}

message IterationResult {
  int32 iteration = 1;
  string partial_response = 2;
  string final_answer = 3;      // Non-empty on final iteration
  double iteration_time = 4;
}

message HealthRequest {}
message HealthResponse {
  bool healthy = 1;
  string version = 2;
  repeated string available_backends = 3;
}
```

### RustReason Sidecar (proto/rustreason/v1/rustreason.proto)

```protobuf
syntax = "proto3";
package rustreason.v1;

service RustReasonService {
  rpc Reason(ReasonRequest) returns (ReasonResponse);
  rpc Query(QueryRequest) returns (QueryResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

message ReasonRequest {
  string graphml = 1;
  repeated string rules = 2;
  repeated InitialFact facts = 3;
  int32 max_timesteps = 4;
}

message InitialFact {
  string node = 1;
  string predicate = 2;
  double lower = 3;
  double upper = 4;
  int32 start_time = 5;
  int32 end_time = 6;
}

message ReasonResponse {
  int32 timesteps = 1;
  bool converged = 2;
  map<string, NodeState> nodes = 3;
  string proof_trace = 4;
}

message NodeState {
  map<string, IntervalValue> predicates = 1;
}

message IntervalValue {
  double lower = 1;
  double upper = 2;
}

message QueryRequest {
  string query = 1;
}

message QueryResponse {
  repeated QueryMatch matches = 1;
}

message QueryMatch {
  string node = 1;
  string predicate = 2;
  double lower = 3;
  double upper = 4;
  int32 timestep = 5;
}

message HealthRequest {}
message HealthResponse {
  bool healthy = 1;
  string version = 2;
}
```

### SynaReason Sidecar (proto/synareason/v1/synareason.proto)

```protobuf
syntax = "proto3";
package synareason.v1;

service SynaReasonService {
  rpc Extract(ExtractRequest) returns (ExtractResponse);
  rpc Reason(ReasoningRequest) returns (ReasoningResponse);
  rpc SessionTurn(SessionTurnRequest) returns (SessionTurnResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}

message ExtractRequest {
  string text = 1;
  string existing_graph_json = 2;
  string backend = 3;
  string model = 4;
}

message ExtractResponse {
  repeated EntityResult entities = 1;
  repeated RelationshipResult relationships = 2;
  repeated string new_rules = 3;
  string proof_tree = 4;
  bool consistent = 5;
}

message EntityResult {
  string name = 1;
  string type = 2;
  map<string, string> properties = 3;
  double confidence = 4;
}

message RelationshipResult {
  string source = 1;
  string target = 2;
  string type = 3;
  double confidence = 4;
}

message ReasoningRequest {
  string graph_json = 1;
  repeated string rules = 2;
  string query = 3;
}

message ReasoningResponse {
  repeated string derivations = 1;
  string proof_tree = 2;
  bool consistent = 3;
  repeated string conflicts = 4;
}

message SessionTurnRequest {
  string session_id = 1;
  string text = 2;
}

message SessionTurnResponse {
  string session_id = 1;
  ExtractResponse extraction = 2;
  ReasoningResponse reasoning = 3;
  string summary = 4;
}

message HealthRequest {}
message HealthResponse {
  bool healthy = 1;
  string version = 2;
  bool llm_available = 3;
}
```

---

## Deployment Architecture

### Personal (Docker Compose + SurrealDB)

```yaml
services:
  axiom:
    build: { context: ., dockerfile: docker/Dockerfile.axiom }
    depends_on:
      keydb: { condition: service_healthy }
      surrealdb: { condition: service_healthy }
      rlm-sidecar: { condition: service_healthy }
    environment:
      GRAPH_BACKEND: surreal
      SURREAL_URL: ws://surrealdb:8000
      SURREAL_NS: axiom
      SURREAL_DB: personal
      KEYDB_URL: redis://keydb:6379
      RLM_ADDR: rlm-sidecar:50051
      RUSTREASON_ADDR: rustreason-sidecar:50052
      SYNAREASON_ADDR: synareason-sidecar:50053
      BEADS_PATH: /data/beads
      CHANNELS_CONFIG: /config/channels.yaml
    volumes:
      - axiom-data:/data
      - ./config:/config:ro
    networks: [axiom-net]

  surrealdb:
    image: surrealdb/surrealdb:v2.2
    command: start --log info file:/data/surreal.db
    volumes: [surreal-data:/data]
    networks: [axiom-net]
    healthcheck:
      test: ["CMD", "surreal", "is-ready"]

  keydb:
    image: eqalpha/keydb:latest
    ports: ["6379:6379"]
    volumes: [keydb-data:/data]
    networks: [axiom-net]
    healthcheck:
      test: ["CMD", "keydb-cli", "ping"]

  rlm-sidecar:
    build: { context: ., dockerfile: docker/Dockerfile.rlm-sidecar }
    environment:
      GRPC_PORT: "50051"
      DEFAULT_BACKEND: anthropic
      DEFAULT_MODEL: claude-sonnet-4-5-20250929
    networks: [axiom-net]
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50051"]

  rustreason-sidecar:
    build: { context: ., dockerfile: docker/Dockerfile.rustreason-sidecar }
    environment: { GRPC_PORT: "50052" }
    networks: [axiom-net]
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50052"]

  synareason-sidecar:
    build: { context: ., dockerfile: docker/Dockerfile.synareason-sidecar }
    environment:
      GRPC_PORT: "50053"
      LLM_BACKEND: anthropic
      LLM_MODEL: claude-sonnet-4-5-20250929
    networks: [axiom-net]
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50053"]

networks:
  axiom-net: { driver: bridge }

volumes:
  axiom-data:
  surreal-data:
  keydb-data:
```

### Enterprise Overlay (docker-compose.enterprise.yml)

Adds to the personal stack:
- **Apache AGE** (PostgreSQL + AGE extension) replacing SurrealDB
- **PRECINCT Gateway** (13-layer middleware chain from reference architecture)
- **SPIFFE/SPIRE** (cryptographic identity for all services)
- **SPIKE Nexus** (encrypted secrets with late-binding token substitution)
- **OPA** (fine-grained policy enforcement)
- **OTel Collector** (OTLP trace/metric export)
- **Phoenix** (trace visualization UI)

```yaml
# docker-compose.enterprise.yml (overlay on docker-compose.yml)
services:
  axiom:
    environment:
      GRAPH_BACKEND: age
      AGE_DSN: host=age-db port=5432 dbname=axiom user=axiom sslmode=verify-full
      AGE_GRAPH: knowledge
      SECURITY_GATEWAY_URL: http://mcp-security-gateway:9090
      SPIFFE_MODE: prod

  age-db:
    image: apache/age:latest
    environment:
      POSTGRES_DB: axiom
      POSTGRES_USER: axiom
      POSTGRES_PASSWORD_FILE: /run/secrets/age_password
    volumes: [age-data:/var/lib/postgresql/data]
    networks: [axiom-net]
    secrets: [age_password]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U axiom"]

  mcp-security-gateway:
    # Inherits from reference architecture
    extends:
      file: ../agentic_reference_architecture/POC/docker-compose.yml
      service: mcp-security-gateway
    networks: [axiom-net]

  # SPIFFE/SPIRE, SPIKE, OPA, OTel inherited from reference architecture
  # See POC/docker-compose.yml for full security stack

volumes:
  age-data:

secrets:
  age_password:
    file: ./secrets/age_password.txt
```

### Kubernetes (Enterprise)

Uses Kustomize with `base/` + `overlays/enterprise/`:

- **base/**: axiom deployment, keydb statefulset, sidecar deployments, configmaps
- **overlays/personal/**: SurrealDB statefulset
- **overlays/enterprise/**: AGE statefulset, gateway deployment, SPIRE daemonset, network policies, pod security standards, resource limits, HPA for cattle agents

---

## What to Reuse vs Build New

### Import Directly (Go Libraries)

| Component | Source | Import Method |
|-----------|--------|---------------|
| Beads Go API | `github.com/steveyegge/beads` | `go get` -- use `beads.Open()`, `store.GetReadyWork()`, `store.ClaimIssue()` |
| AGE Go driver | `~/workspace/HAGIBOT/allage/age/drivers/golang/` | Vendor or publish as Go module |
| KeyDB client | `github.com/redis/go-redis/v9` | Already used in reference architecture |
| gRPC | `google.golang.org/grpc` | Standard Go gRPC |
| OTel | `go.opentelemetry.io/otel` | Already used in reference architecture |
| OPA | `github.com/open-policy-agent/opa` | Already used in reference architecture |

### Port Patterns (Not Code)

| Pattern | Source | What to Replicate |
|---------|--------|-------------------|
| Middleware chain | Ref arch `internal/gateway/gateway.go` | Reverse-wrapping `handler = middleware.X(handler, ...)` pattern |
| Store interface | Ref arch `middleware/session_store.go` | Interface + InMemory + Production dual implementation |
| Docker Compose networking | Ref arch `docker-compose.yml` | Health checks, named networks, init containers, secret mounting |
| OTel span per layer | Ref arch all middleware | `tracer.Start(ctx, "axiom.step_name", trace.WithAttributes(...))` |
| Error codes | Ref arch structured errors | Actionable error codes with middleware identification |
| Table-driven tests | Ref arch `*_test.go` | Exhaustive test tables with miniredis for KeyDB |

### Wrap via gRPC Sidecar (Polyglot)

| Sidecar | Wraps | Source |
|---------|-------|--------|
| rlm-sidecar (Python) | `rlm.RLM().completion()` | `~/workspace/rlm/rlm/core/rlm.py` |
| rustreason-sidecar (Rust) | `rustreason_core::ReasoningEngine` | `~/workspace/rustreason/crates/rustreason-core/` |
| synareason-sidecar (Python) | `synareason.Session` | `~/workspace/exp/synareason/src/` |

### Build New

| Component | Why New |
|-----------|---------|
| Channel adapters | Each platform API is unique; port channel list from case-study sources but implement fresh in Go |
| GraphStore interface + AGE/SurrealDB backends | New abstraction needed; AGE and SurrealDB have very different query languages |
| RLM-based agent loop | Novel combination of RLM recursion with beads work queue and knowledge graph context |
| Swarm dispatcher | New routing logic: channels -> beads -> agents -> responses |
| Pet agents | Domain-specific maintenance logic for each role |
| Bus implementation | Reference arch uses KeyDB for sessions, not Streams -- new usage pattern |
| Knowledge graph schema | New domain model for continual learning with temporal properties |

---

## Implementation Phases

### Phase 1: Foundation
- Go module init (`go mod init`), core interfaces in `pkg/`
- In-memory implementations for all interfaces (testing scaffolds)
- Protobuf definitions + codegen setup (`buf generate`)
- Makefile with build/test/lint/proto targets
- Unit tests for all interfaces
- `.beads/` initialization

### Phase 2: Bus + Beads Integration
- KeyDB Redis Streams bus implementation (`XADD`, `XREADGROUP`, `XACK`)
- `BeadsClient` wrapping `beads.Storage` for agent use
- Bus -> Beads coordination tests
- Integration tests with real KeyDB (no mocks)

### Phase 3: Agent Loop + RLM Sidecar
- Python gRPC sidecar wrapping `rlm.RLM().completion()`
- Go gRPC client for RLM sidecar
- Basic cattle agent loop (claim from beads -> call RLM -> complete bead)
- Docker Compose: axiom + keydb + rlm-sidecar
- First working E2E: submit work via CLI -> agent processes -> result in beads

### Phase 4: Graph Store
- SurrealDB `GraphStore` implementation (personal)
- Apache AGE `GraphStore` implementation (enterprise)
- Knowledge graph schema initialization (node labels, edge labels)
- Context loading in agent loop (graph query before RLM call)
- Integration tests with real SurrealDB and real AGE

### Phase 5: Channels
- Telegram adapter (first channel, most straightforward bot API)
- Dispatcher: `channel.inbound` -> create bead -> agent claims -> response -> `channel.outbound`
- Discord adapter (second channel)
- Full E2E conversational flow test

### Phase 6: Reasoning Sidecars
- RustReason gRPC sidecar (Rust binary with tonic)
- SynaReason gRPC sidecar (Python)
- Unified `Reasoner` client in Go wrapping all three sidecars
- High-stakes routing logic (confidence threshold -> formal verification)
- Proof tree recording in audit log

### Phase 7: Pet Agents
- Pet agent framework (registry, heartbeat protocol, scheduling)
- Curator implementation (knowledge graph maintenance)
- Timekeeper implementation (TTL, liveness, deferred activation)
- Scheduler implementation (cron evaluation)

### Phase 8: Security + Enterprise
- Tool calls routed through 13-layer security gateway
- Enterprise Docker Compose overlay (AGE + SPIFFE + SPIKE + OPA + OTel)
- Sentinel pet agent (security monitoring, anomaly detection)
- Librarian pet agent (document management, citation tracking)
- Audit integration (proof trees in audit journal)

### Phase 9: Kubernetes + Production
- K8s manifests (base + personal overlay + enterprise overlay)
- Health checks, readiness probes, resource limits
- HPA for cattle agents (scale on beads queue depth)
- OTel instrumentation across all Go components
- Production runbook and operational documentation

---

## Verification Strategy

After each phase:

1. **Unit tests**: `make test` -- 80%+ coverage, mocks allowed
2. **Integration tests**: `make test-integration` -- real KeyDB, real graph DB, NO mocks
3. **E2E tests**: `make test-e2e` -- full Docker Compose stack, conversational flow
4. **Beads audit**: `bd list --status=closed` -- all phase issues completed
5. **OTel traces**: Verify span hierarchy in Phoenix UI

Phase 3 milestone (first working pipeline):
```bash
make up                          # Start personal stack
axctl channel add telegram       # Configure Telegram
# Send message via Telegram
# Verify: bead created -> RLM called -> response delivered -> bead closed
bd list --status=closed          # Confirm work item lifecycle
```

Phase 8 milestone (enterprise-ready):
```bash
make up-enterprise               # Start enterprise stack
# Verify: tool calls pass through 13-layer gateway
# Verify: proof trees in audit journal for high-stakes decisions
# Verify: sentinel detects anomalous patterns
make compliance-report           # Generate SOC 2/ISO 27001 evidence
```

---

## Makefile Targets

```makefile
.PHONY: help build test lint proto up down logs clean

help:                ## Show available targets
build:               ## Build axiom and axctl binaries
proto:               ## Generate Go code from protobuf definitions (buf generate)
lint:                ## Run golangci-lint
test:                ## Run unit tests with race detection
test-integration:    ## Run integration tests (requires docker compose up)
test-e2e:            ## Run end-to-end tests
test-coverage:       ## Run tests with coverage report
up:                  ## Start personal Docker Compose stack (SurrealDB)
up-enterprise:       ## Start enterprise Docker Compose stack (AGE + security)
down:                ## Stop Docker Compose stack
logs:                ## Tail all container logs
dev:                 ## Run axiom locally (outside Docker)
clean:               ## Remove build artifacts
k8s-up:              ## Deploy to Kubernetes (personal overlay)
k8s-enterprise:      ## Deploy to Kubernetes (enterprise overlay)
k8s-down:            ## Remove Kubernetes deployment
```
