// Package redis provides reusable Redis Stream publish/subscribe wrappers
// for all SPECTRE Go microservices.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps a go-redis client with stream-specific helpers.
type Client struct {
	rdb *redis.Client
}

// StreamMessage represents a decoded message from a Redis stream.
type StreamMessage struct {
	ID     string
	Stream string
	Data   map[string]interface{}
}

// NewClient creates a new Redis client. It reads REDIS_ADDR from the
// environment, defaulting to "redis:6379".
func NewClient() *Client {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "redis:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[redis] failed to connect to %s: %v", addr, err)
	}
	log.Printf("[redis] connected to %s", addr)

	return &Client{rdb: rdb}
}

// Publish adds a message to a Redis stream via XADD.
// The data map is JSON-serialized into a single "payload" field.
func (c *Client) Publish(ctx context.Context, stream string, data map[string]interface{}) (string, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	id, err := c.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"payload": string(payload),
		},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("XADD to %s failed: %w", stream, err)
	}

	return id, nil
}

// EnsureConsumerGroup creates a consumer group on a stream if it doesn't
// already exist. It starts reading from the beginning ("0").
func (c *Client) EnsureConsumerGroup(ctx context.Context, stream, group string) error {
	err := c.rdb.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil {
		// "BUSYGROUP" means the group already exists — not a real error
		if err.Error() == "BUSYGROUP Consumer Group name already exists" {
			return nil
		}
		return fmt.Errorf("XGroupCreate on %s/%s failed: %w", stream, group, err)
	}
	return nil
}

// Subscribe listens on a Redis stream consumer group. It calls handler for
// each message. This blocks forever and should be run in a goroutine.
func (c *Client) Subscribe(ctx context.Context, stream, group, consumer string, handler func(StreamMessage) error) error {
	if err := c.EnsureConsumerGroup(ctx, stream, group); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		results, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    group,
			Consumer: consumer,
			Streams:  []string{stream, ">"},
			Count:    10,
			Block:    2 * time.Second,
		}).Result()
		if err != nil {
			if err == redis.Nil {
				continue // timeout, no new messages
			}
			log.Printf("[redis] XReadGroup error on %s: %v", stream, err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, result := range results {
			for _, msg := range result.Messages {
				payloadStr, ok := msg.Values["payload"].(string)
				if !ok {
					log.Printf("[redis] skipping message %s: no payload field", msg.ID)
					// ACK it anyway so we don't get stuck
					c.rdb.XAck(ctx, stream, group, msg.ID)
					continue
				}

				var data map[string]interface{}
				if err := json.Unmarshal([]byte(payloadStr), &data); err != nil {
					log.Printf("[redis] skipping message %s: unmarshal error: %v", msg.ID, err)
					c.rdb.XAck(ctx, stream, group, msg.ID)
					continue
				}

				sm := StreamMessage{
					ID:     msg.ID,
					Stream: result.Stream,
					Data:   data,
				}

				if err := handler(sm); err != nil {
					log.Printf("[redis] handler error for %s on %s: %v", msg.ID, stream, err)
				}

				// ACK processed message
				c.rdb.XAck(ctx, stream, group, msg.ID)
			}
		}
	}
}

// ReadStream reads the latest N messages from a stream (without consumer
// groups). Useful for the SSE endpoint that fans out to dashboard clients.
func (c *Client) ReadStream(ctx context.Context, stream string, lastID string, count int64) ([]StreamMessage, error) {
	if lastID == "" {
		lastID = "0"
	}

	results, err := c.rdb.XRead(ctx, &redis.XReadArgs{
		Streams: []string{stream, lastID},
		Count:   count,
		Block:   5 * time.Second,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // no new messages
		}
		return nil, err
	}

	var messages []StreamMessage
	for _, result := range results {
		for _, msg := range result.Messages {
			payloadStr, ok := msg.Values["payload"].(string)
			if !ok {
				continue
			}
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(payloadStr), &data); err != nil {
				continue
			}
			messages = append(messages, StreamMessage{
				ID:     msg.ID,
				Stream: result.Stream,
				Data:   data,
			})
		}
	}

	return messages, nil
}

// ReadStreamNonBlocking reads the latest N messages from a stream without
// blocking. Returns empty slice immediately if no new messages exist.
// This prevents the SSE fan-out loop from freezing on streams with no data.
func (c *Client) ReadStreamNonBlocking(ctx context.Context, stream string, lastID string, count int64) ([]StreamMessage, error) {
	if lastID == "" {
		lastID = "0"
	}

	results, err := c.rdb.XRangeN(ctx, stream, "("+lastID, "+", count).Result()
	if err != nil {
		return nil, err
	}

	var messages []StreamMessage
	for _, msg := range results {
		payloadStr, ok := msg.Values["payload"].(string)
		if !ok {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(payloadStr), &data); err != nil {
			continue
		}
		messages = append(messages, StreamMessage{
			ID:     msg.ID,
			Stream: stream,
			Data:   data,
		})
	}

	return messages, nil
}

// Close shuts down the Redis client connection.
func (c *Client) Close() error {
	return c.rdb.Close()
}
