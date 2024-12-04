package filecache

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type v2 struct {
	creds *credentials.Credentials
}

var _ aws.CredentialsProvider = &v2{}

func (p *v2) Retrieve(ctx context.Context) (aws.Credentials, error) {
	val, err := p.creds.GetWithContext(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	resp := aws.Credentials{
		AccessKeyID:     val.AccessKeyID,
		SecretAccessKey: val.SecretAccessKey,
		SessionToken:    val.SessionToken,
		Source:          val.ProviderName,
		CanExpire:       false,
		// Don't have account ID
	}

	if expiration, err := p.creds.ExpiresAt(); err == nil {
		resp.CanExpire = true
		resp.Expires = expiration
	}
	return resp, nil
}

// V1ProviderToV2Provider converts a v1 credentials.Provider to a v2 aws.CredentialsProvider
func V1ProviderToV2Provider(p credentials.Provider) aws.CredentialsProvider {
	return V1CredentialToV2Provider(credentials.NewCredentials(p))
}

// V1CredentialToV2Provider converts a v1 credentials.Credential to a v2 aws.CredentialProvider
func V1CredentialToV2Provider(c *credentials.Credentials) aws.CredentialsProvider {
	return &v2{creds: c}
}

// V2CredentialToV1Value converts a v2 aws.Credentials to a v1 credentials.Value
func V2CredentialToV1Value(cred aws.Credentials) credentials.Value {
	return credentials.Value{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
		SessionToken:    cred.SessionToken,
		ProviderName:    cred.Source,
	}
}
