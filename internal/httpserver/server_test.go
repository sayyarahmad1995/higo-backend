package httpserver

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeDrainsActiveRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverCtx, stop := context.WithCancel(ctx)
	defer stop()

	listening := make(chan string, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	shuttingDown := make(chan struct{})
	server := &http.Server{
		Addr: "127.0.0.1:0",
		BaseContext: func(listener net.Listener) context.Context {
			listening <- listener.Addr().String()
			return context.Background()
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			select {
			case <-release:
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			case <-ctx.Done():
			}
		}),
	}
	defer server.Close()
	server.RegisterOnShutdown(func() { close(shuttingDown) })
	done := make(chan error, 1)
	go func() { done <- serve(serverCtx, server) }()

	var address string
	select {
	case address = <-listening:
	case err := <-done:
		t.Fatalf("server exited before listening: %v", err)
	case <-ctx.Done():
		t.Fatal("server did not start")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response := make(chan int, 1)
	requestError := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			requestError <- err
			return
		}
		defer resp.Body.Close()
		response <- resp.StatusCode
	}()
	select {
	case <-started:
	case err := <-requestError:
		t.Fatalf("request failed before reaching the handler: %v", err)
	case <-ctx.Done():
		t.Fatal("request did not reach the handler")
	}

	stop()
	select {
	case <-shuttingDown:
	case <-ctx.Done():
		t.Fatal("server did not begin graceful shutdown")
	}
	close(release)

	select {
	case status := <-response:
		if status != http.StatusNoContent {
			t.Fatalf("response status = %d, want 204", status)
		}
	case err := <-requestError:
		t.Fatalf("in-flight request failed during shutdown: %v", err)
	case <-ctx.Done():
		t.Fatal("in-flight request did not complete")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned an error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not exit after the request completed")
	}
}
