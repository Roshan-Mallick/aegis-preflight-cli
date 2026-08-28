package session

import (
	"fmt"
)

type State string

const (
	StateCreated            State = "CREATED"
	StateSnapshotting       State = "SNAPSHOTTING_PROJECT"
	StateSandboxStarted     State = "SANDBOX_STARTED"
	StateAgentStarted       State = "AGENT_STARTED"
	StateActive             State = "ACTIVE"
	StateAgentFinished      State = "AGENT_FINISHED"
	StateSecurityScan       State = "SECURITY_SCAN"
	StatePreflight          State = "PREFLIGHT"
	StateBlock              State = "BLOCK"
	StatePass               State = "PASS"
	StateCleanup            State = "CLEANUP"
	StateClosed             State = "CLOSED"
	StatePreservingEvidence State = "PRESERVING_EVIDENCE"
	StateTerminated         State = "TERMINATED"
	StateFailed             State = "FAILED"
)

// Backward-compatible aliases.
const (
	StateStarting     = StateSandboxStarted
	StateRunning      = StateActive
	StateMonitoring   = StateActive
	StateBlocked      = StateBlock
	StateAgentExited  = StateAgentFinished
	StateFixing       = StatePreflight
	StateVerified     = StatePass
	StateReleaseReady = StateClosed
)

var transitions = map[State][]State{
	StateCreated:            {StateSnapshotting, StateFailed},
	StateSnapshotting:       {StateSandboxStarted, StateFailed},
	StateSandboxStarted:     {StateAgentStarted, StateActive, StateFailed},
	StateAgentStarted:       {StateActive, StateFailed},
	StateActive:             {StateAgentFinished, StateBlock, StatePreservingEvidence, StateFailed, StateActive},
	StateAgentFinished:      {StateSecurityScan, StatePreflight, StateFailed},
	StateSecurityScan:       {StatePreflight, StateFailed},
	StatePreflight:          {StateBlock, StatePass, StatePreflight, StateFailed},
	StateBlock:              {StateCleanup, StateActive, StateAgentFinished, StatePreservingEvidence, StateFailed},
	StatePass:               {StateCleanup, StateClosed, StateFailed},
	StateCleanup:            {StateClosed, StateFailed},
	StateClosed:             {},
	StatePreservingEvidence: {StateTerminated},
	StateTerminated:         {},
	StateFailed:             {},
}

func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

func IsTerminal(s State) bool {
	return len(transitions[s]) == 0
}

type IllegalTransitionError struct {
	From State
	To   State
}

func (e *IllegalTransitionError) Error() string {
	return fmt.Sprintf("illegal session state transition %s -> %s", e.From, e.To)
}

func SeverityForState(s State) string {
	switch s {
	case StatePreservingEvidence, StateTerminated:
		return "critical"
	case StateBlock:
		return "high"
	case StatePreflight, StateActive:
		return "medium"
	default:
		return "info"
	}
}
