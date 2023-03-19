package internal

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/cloudflare-go"
)

type CloudflareAuth struct {
	CloudflareZoneId   string
	CloudflareApiToken string

	api *cloudflare.API
}

func (auth *CloudflareAuth) setup() {
	fmt.Println("setup cloudflare api!!")
	api, err := cloudflare.NewWithAPIToken(auth.CloudflareApiToken)
	if err != nil {
		log.Fatal(err)
	}
	auth.api = api
}

func (auth *CloudflareAuth) ListChallengeRecord(ctx context.Context) []string {
	if auth.api == nil {
		auth.setup()
	}

	var recordIds []string
	resC := cloudflare.ResourceContainer{Level: cloudflare.RouteLevel("zones"), Identifier: auth.CloudflareZoneId}
	records, _, err := auth.api.ListDNSRecords(ctx, &resC, cloudflare.ListDNSRecordsParams{Comment: "acme-challenge"})
	if err != nil {
		return nil
	}
	for _, record := range records {
		recordIds = append(recordIds, record.ID)
	}
	return recordIds
}

func (auth *CloudflareAuth) UpdateOrInsertChallengeRecord(ctx context.Context, name string, token string) error {
	auth.DelChallengeRecord(ctx)
	if auth.api == nil {
		auth.setup()
	}

	resC := cloudflare.ResourceContainer{Level: cloudflare.RouteLevel("zones"), Identifier: auth.CloudflareZoneId}
	dnsParams := cloudflare.CreateDNSRecordParams{
		Name:    name,
		Type:    "TXT",
		Content: token,
		TTL:     60,
		Comment: "acme-challenge",
	}

	resp, err := auth.api.CreateDNSRecord(ctx, &resC, dnsParams)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp)
	time.Sleep(30 * time.Second)
	return nil
}

func (auth *CloudflareAuth) DelChallengeRecord(ctx context.Context) {
	recordIds := auth.ListChallengeRecord(ctx)
	if recordIds != nil {
		return
	}

	if auth.api == nil {
		auth.setup()
	}

	resC := cloudflare.ResourceContainer{Level: cloudflare.RouteLevel("zones"), Identifier: auth.CloudflareZoneId}
	for _, id := range recordIds {
		err := auth.api.DeleteDNSRecord(ctx, &resC, id)
		if err != nil {
			return
		}
	}
	time.Sleep(31 * time.Second)
}
