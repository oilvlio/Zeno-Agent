package agent

import "errors"

func newTestClient(baseURL, nodeID, token string) *Client {
	return NewClientWithOptions(baseURL, nodeID, token, ClientOptions{})
}

func isAgentAPIStatus(err error, statusCode int) bool {
	var statusErr *AgentAPIStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

// Load is test-only inspection support. Production consumes pending items
// through Next, which applies due-time and TTL rules before upload.
func (s *ProbeSpool) Load(id string) (*ProbeSpoolItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.pendingPathLocked(id)
	if err != nil {
		return nil, err
	}
	envelope, _, err := s.readEnvelopeLocked(path)
	if err != nil {
		return nil, err
	}
	return probeSpoolItemFromEnvelope(id, envelope), nil
}
