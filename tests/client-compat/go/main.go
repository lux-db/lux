package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func newClient(host string, port int, password string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", host, port),
		Password: password,
		Protocol: 2,
	})
}

func main() {
	port, err := strconv.Atoi(os.Getenv("LUX_COMPAT_PORT"))
	must(err)
	password := os.Getenv("LUX_COMPAT_PASSWORD")
	host := os.Getenv("LUX_COMPAT_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := newClient(host, port, password)
	must(client.FlushDB(ctx).Err())
	must(client.Set(ctx, "go:key", []byte{0x00, 0x80, 0xff}, 0).Err())
	value, err := client.Get(ctx, "go:key").Bytes()
	must(err)
	if string(value) != string([]byte{0x00, 0x80, 0xff}) {
		panic("binary value changed")
	}

	pipe := client.Pipeline()
	pipe.Set(ctx, "go:pipe", "1", 0)
	incremented := pipe.Incr(ctx, "go:pipe")
	_, err = pipe.Exec(ctx)
	must(err)
	if incremented.Val() != 2 {
		panic("pipeline returned the wrong value")
	}

	_, err = client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, "go:tx", "1", 0)
		pipe.Incr(ctx, "go:tx")
		return nil
	})
	must(err)

	must(client.RPush(ctx, "go:blocking", "ready").Err())
	blocked, err := client.BLPop(ctx, time.Second, "go:blocking").Result()
	must(err)
	if len(blocked) != 2 || blocked[1] != "ready" {
		panic("blocking pop returned the wrong value")
	}

	pubsub := client.Subscribe(ctx, "go:events")
	_, err = pubsub.Receive(ctx)
	must(err)
	must(client.Publish(ctx, "go:events", "ready").Err())
	message, err := pubsub.ReceiveMessage(ctx)
	must(err)
	if message.Payload != "ready" {
		panic("pub/sub returned the wrong payload")
	}
	must(pubsub.Close())
	must(client.Close())

	reconnected := newClient(host, port, password)
	defer reconnected.Close()
	if got, err := reconnected.Get(ctx, "go:tx").Result(); err != nil || got != "2" {
		panic("reconnect did not preserve the expected value")
	}
	fmt.Println("client: go-redis 9.22.0")
}
