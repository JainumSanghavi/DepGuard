package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/depguard/depguard/internal/parser"
)

const (
	batchURL      = "https://api.osv.dev/v1/querybatch"
	vulnDetailFmt = "https://api.osv.dev/v1/vulns/%s"
	concurrency   = 10
)

// Client queries the OSV API and caches vuln details in memory.
type Client struct {
	http  *http.Client
	mu    sync.Mutex
	cache map[string]*VulnDetail
}

// NewClient returns a new Client with an empty cache.
func NewClient() *Client {
	return &Client{
		http:  &http.Client{},
		cache: make(map[string]*VulnDetail),
	}
}

// QueryBatch sends all deps in a single POST /v1/querybatch and returns a map
// from dependency index to the list of vuln IDs for that dep.
func (c *Client) QueryBatch(ctx context.Context, deps []parser.Dependency) (map[int][]string, error) {
	queries := make([]Query, len(deps))
	for i, d := range deps {
		queries[i] = Query{
			Package: Package{Name: d.Name, Ecosystem: d.Ecosystem},
			Version: d.Version,
		}
	}

	body, err := json.Marshal(BatchQuery{Queries: queries})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, batchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv querybatch: status %d", resp.StatusCode)
	}

	var result BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	out := make(map[int][]string)
	for i, r := range result.Results {
		for _, v := range r.Vulns {
			out[i] = append(out[i], v.ID)
		}
	}
	return out, nil
}

// FetchDetails concurrently fetches full VulnDetail for each ID in ids using a
// worker pool (max concurrency=10) and an in-memory cache.
func (c *Client) FetchDetails(ctx context.Context, ids []string) (map[string]*VulnDetail, error) {
	results := make(map[string]*VulnDetail, len(ids))
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	g, gctx := errgroup.WithContext(ctx)

	for _, id := range ids {
		id := id

		c.mu.Lock()
		cached, hit := c.cache[id]
		c.mu.Unlock()

		if hit {
			mu.Lock()
			results[id] = cached
			mu.Unlock()
			continue
		}

		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			defer func() { <-sem }()

			detail, err := c.fetchOne(gctx, id)
			if err != nil {
				return err
			}

			c.mu.Lock()
			c.cache[id] = detail
			c.mu.Unlock()

			mu.Lock()
			results[id] = detail
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Client) fetchOne(ctx context.Context, id string) (*VulnDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(vulnDetailFmt, id), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv fetch %s: status %d", id, resp.StatusCode)
	}

	const maxBody = 10 << 20 // 10 MB
	var detail VulnDetail
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}
