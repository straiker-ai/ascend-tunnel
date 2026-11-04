package agentclient

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

// Straiker Broker's records, as the signed-in person reads and writes them. Every call needs the integration:write
// scope.
const (
	brokerPath     = "/api/v3/broker"
	maxBrokerPages = 50
	// BrokerActive is a broker whose key the relay accepts; a revoked broker's key is refused for good.
	BrokerActive = "active"
)

// Broker is one registered straiker-broker key.
type Broker struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
}

// BrokerTarget is a host a broker reaches, and the products allowed to route to it.
type BrokerTarget struct {
	ID       string   `json:"id"`
	BrokerID string   `json:"broker_id"`
	Name     string   `json:"name"`
	Port     int      `json:"port"`
	Products []string `json:"products"`
}

// Brokers is every broker of the org, revoked ones included.
func (c *Client) Brokers(ctx context.Context) ([]Broker, error) {
	return listAll[Broker](ctx, c, brokerPath+"/brokers")
}

// RegisterBroker registers a straiker-broker public key. A 409 broker_exists means an active broker already has it.
func (c *Client) RegisterBroker(ctx context.Context, publicKey, label string) (*Broker, error) {
	var b Broker
	if err := c.PostJSON(ctx, brokerPath+"/brokers", map[string]string{"public_key": publicKey, "label": label}, &b); err != nil {
		return nil, err
	}
	if b.ID == "" {
		return nil, errors.New("Straiker's answer named no broker")
	}
	return &b, nil
}

// BrokerTargets is every broker target of the org, across brokers.
func (c *Client) BrokerTargets(ctx context.Context) ([]BrokerTarget, error) {
	return listAll[BrokerTarget](ctx, c, brokerPath+"/targets")
}

// CreateBrokerTarget declares a host a broker reaches; no product may use it until granted. A 409 target_exists
// means the broker already has the name, at any port.
func (c *Client) CreateBrokerTarget(ctx context.Context, brokerID, name string, port int, label string) (*BrokerTarget, error) {
	var t BrokerTarget
	body := map[string]any{"broker_id": brokerID, "name": name, "port": port, "label": label}
	if err := c.PostJSON(ctx, brokerPath+"/targets", body, &t); err != nil {
		return nil, err
	}
	if t.ID == "" {
		return nil, errors.New("Straiker's answer named no broker target")
	}
	return &t, nil
}

// SetBrokerGrants replaces the products allowed on a target: one left out is revoked.
func (c *Client) SetBrokerGrants(ctx context.Context, targetID string, products []string) error {
	var t BrokerTarget
	path := brokerPath + "/targets/" + url.PathEscape(targetID) + "/grants"
	return c.PutJSON(ctx, path, map[string][]string{"products": products}, &t)
}

// listAll walks a broker list's pages, refusing a partial list.
func listAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	cursor := ""
	for range maxBrokerPages {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			Data       []T    `json:"data"`
			HasMore    bool   `json:"has_more"`
			NextCursor string `json:"next_cursor"`
		}
		if err := c.GetJSON(ctx, path, q, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Data...)
		if !page.HasMore || page.NextCursor == "" || page.NextCursor == cursor {
			return out, nil
		}
		cursor = page.NextCursor
	}
	return nil, fmt.Errorf("%s still has more after %d pages", path, maxBrokerPages)
}
