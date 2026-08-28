package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/eth0x1/aegis/internal/events"
)

const metadataFileName = "metadata.json"

func Dir(stateRoot, id string) string {
	return filepath.Join(stateRoot, "sessions", id)
}

func NewID() string { return uuid.NewString() }

type Metadata struct {
	SessionID       string   `json:"session_id"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
	ProjectRoot     string   `json:"project_root,omitempty"`
	Workspace       string   `json:"workspace,omitempty"`
	Agent           string   `json:"agent"`
	NetProfile      string   `json:"net_profile"`
	State           State    `json:"state"`
	Outcome         string   `json:"outcome,omitempty"`
	IncidentIDs     []string `json:"incident_ids,omitempty"`
	PreflightCycles int      `json:"preflight_cycles"`
}

type Manager struct {
	mu    sync.Mutex
	Meta  Metadata
	dir   string
	store *events.Store
}

func (m *Manager) Snapshot() Metadata {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Meta
}

func Create(stateRoot, projectRoot, agent, netProfile string) (*Manager, error) {
	id := NewID()
	dir := Dir(stateRoot, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	m := &Manager{
		Meta: Metadata{
			SessionID:   id,
			CreatedAt:   now,
			UpdatedAt:   now,
			ProjectRoot: projectRoot,
			Agent:       agent,
			NetProfile:  netProfile,
			State:       StateCreated,
		},
		dir: dir,
	}
	if err := m.saveMetadataLocked(); err != nil {
		return nil, err
	}
	st, err := events.Open(dir)
	if err != nil {
		return nil, err
	}
	m.store = st
	ev := events.New(events.SourcePolicy, events.TypeSessionCreated, events.SevInfo, "aegis", id, map[string]any{
		"project_root": projectRoot,
		"agent":        agent,
		"net_profile":  netProfile,
	})
	if err := m.store.Append(ev); err != nil {
		return nil, err
	}
	return m, nil
}

func Load(stateRoot, id string) (*Manager, error) {
	dir := Dir(stateRoot, id)
	b, err := os.ReadFile(filepath.Join(dir, metadataFileName))
	if err != nil {
		return nil, fmt.Errorf("load session %s: %w", id, err)
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("parse session %s metadata: %w", id, err)
	}
	if _, err := uuid.Parse(meta.SessionID); err != nil {
		return nil, fmt.Errorf("session %s has invalid session_id", id)
	}
	st, err := events.Open(dir)
	if err != nil {
		return nil, err
	}
	return &Manager{Meta: meta, dir: dir, store: st}, nil
}

func (m *Manager) Dir() string { return m.dir }

func (m *Manager) Store() *events.Store { return m.store }

func (m *Manager) Transition(to State, detail map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	from := m.Meta.State
	if !CanTransition(from, to) {
		return &IllegalTransitionError{From: from, To: to}
	}
	if detail == nil {
		detail = map[string]any{}
	}
	m.Meta.State = to
	m.Meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.saveMetadataLocked(); err != nil {
		return err
	}
	data := map[string]any{"from": string(from), "to": string(to)}
	for k, v := range detail {
		data[k] = v
	}
	ev := events.New(events.SourcePolicy, events.TypeSessionState, SeverityForState(to), "aegis", m.Meta.SessionID, data)
	return m.store.Append(ev)
}

func (m *Manager) SetWorkspace(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Meta.Workspace = path
	m.Meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return m.saveMetadataLocked()
}

func (m *Manager) SetOutcome(outcome string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Meta.Outcome = outcome
	m.Meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return m.saveMetadataLocked()
}

func (m *Manager) AddIncident(incidentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Meta.IncidentIDs = append(m.Meta.IncidentIDs, incidentID)
	m.Meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return m.saveMetadataLocked()
}

func (m *Manager) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

func (m *Manager) saveMetadataLocked() error {
	b, err := json.MarshalIndent(m.Meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	path := filepath.Join(m.dir, metadataFileName)
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("enforce metadata permissions: %w", err)
	}
	return nil
}
