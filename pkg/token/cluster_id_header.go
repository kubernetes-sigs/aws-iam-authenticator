package token

import (
	"context"
	"fmt"

	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
)

type withClusterIDHeader struct {
	clusterID string
}

// implements middleware.BuildMiddleware, which runs AFTER a request has been
// serialized and can operate on the transport request
var _ smithymiddleware.BuildMiddleware = (*withClusterIDHeader)(nil)

func (*withClusterIDHeader) ID() string {
	return "withClusterIDHeader"
}

func (m *withClusterIDHeader) HandleBuild(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (
	out smithymiddleware.BuildOutput, metadata smithymiddleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unrecognized transport type %T", in.Request)
	}
	req.Header.Set(clusterIDHeader, m.clusterID)
	return next.HandleBuild(ctx, in)
}

// WithClusterIDHeader adds the clusterID header to the request befor signing
func WithClusterIDHeader(clusterID string) func(*sts.Options) {
	return func(o *sts.Options) {
		o.APIOptions = append(o.APIOptions, func(s *smithymiddleware.Stack) error {
			return s.Build.Add(&withClusterIDHeader{
				clusterID: clusterID,
			}, smithymiddleware.After)
		})
	}
}
