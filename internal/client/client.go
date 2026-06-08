// Package client holds gRPC clients to the internal Auth and User services.
package client

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/malvinpratama/iam-go-contracts/gen/auth/v1"
	userv1 "github.com/malvinpratama/iam-go-contracts/gen/user/v1"
	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

// tokenInjector appends the shared internal token to every outgoing call so the
// services can authenticate that the caller is the gateway (defense-in-depth).
func tokenInjector(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, grpcutil.MDInternalToken, token)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// Clients bundles the downstream service stubs.
type Clients struct {
	Auth authv1.AuthServiceClient
	User userv1.UserServiceClient

	conns []*grpc.ClientConn
}

// Dial connects to the auth and user services (plaintext on the internal
// network). The internalToken authenticates the gateway to the services.
func Dial(authAddr, userAddr, internalToken string) (*Clients, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(tokenInjector(internalToken)),
	}

	authConn, err := grpc.NewClient(authAddr, opts...)
	if err != nil {
		return nil, err
	}
	userConn, err := grpc.NewClient(userAddr, opts...)
	if err != nil {
		authConn.Close()
		return nil, err
	}
	return &Clients{
		Auth:  authv1.NewAuthServiceClient(authConn),
		User:  userv1.NewUserServiceClient(userConn),
		conns: []*grpc.ClientConn{authConn, userConn},
	}, nil
}

// Close shuts down all connections.
func (c *Clients) Close() {
	for _, conn := range c.conns {
		_ = conn.Close()
	}
}
