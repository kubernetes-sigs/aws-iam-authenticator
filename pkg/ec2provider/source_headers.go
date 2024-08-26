package ec2provider

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
)

const (
	// Headers for STS request for source ARN
	headerSourceArn = "x-amz-source-arn"
	// Headers for STS request for source account
	headerSourceAccount = "x-amz-source-account"
)

type withSourceHeaders struct {
	sourceARN string
}

// implements middleware.BuildMiddleware, which runs AFTER a request has been
// serialized and can operate on the transport request
var _ smithymiddleware.BuildMiddleware = (*withSourceHeaders)(nil)

func (*withSourceHeaders) ID() string {
	return "withSourceHeaders"
}

func (m *withSourceHeaders) HandleBuild(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (
	out smithymiddleware.BuildOutput, metadata smithymiddleware.Metadata, err error,
) {
	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unrecognized transport type %T", in.Request)
	}

	if arn.IsARN(m.sourceARN) {
		req.Header.Set(headerSourceArn, m.sourceARN)
	}

	if parsedArn, err := arn.Parse(m.sourceARN); err == nil && parsedArn.AccountID != "" {
		req.Header.Set(headerSourceAccount, parsedArn.AccountID)
	}

	return next.HandleBuild(ctx, in)
}

// WithSourceHeaders adds the x-amz-source-arn and x-amz-source-account headers to the request.
// These can be referenced in an IAM role trust policy document with the condition keys
// aws:SourceArn and aws:SourceAccount for sts:AssumeRole calls
//
// If the sourceARN is invalid, the source arn header is skipped. If the ARN is valid but doesn't
// contain an account ID, the source account header is skipped
func WithSourceHeaders(sourceARN string) func(*sts.Options) {
	return func(o *sts.Options) {
		o.APIOptions = append(o.APIOptions, func(s *smithymiddleware.Stack) error {
			return s.Build.Add(&withSourceHeaders{
				sourceARN: sourceARN,
			}, smithymiddleware.After)
		})
	}
}
