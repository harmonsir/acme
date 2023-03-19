package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/harmonsir/acme/internal"
	"golang.org/x/crypto/acme"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Domains    []string `yaml:"domains"`
	Directory  string   `yaml:"directory"`
	RegInfo    string   `yaml:"reginfo"`
	EABKeyID   string   `yaml:"EAB_KEY_ID"`
	EABHMACKey string   `yaml:"EAB_HMAC_KEY"`

	CloudflareAPIToken string `yaml:"CLOUDFLARE_API_TOKEN"`
	CloudflareZoneID   string `yaml:"CLOUDFLARE_ZONE_ID"`

	AfterSetupScript string `yaml:"AFTER_SETUP_SCRIPT"`
	SavingCerPath    string `yaml:"SAVING_CER_PATH"`
	SavingKeyPath    string `yaml:"SAVING_KEY_PATH"`
}

func loadConfig() Config {
	// Load YAML file
	data, err := os.ReadFile("config.yml")
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}

	// Parse YAML data into Config struct
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("failed to parse config file: %v", err)
	}
	config.RegInfo = "mailto:" + config.RegInfo
	return config
}

func EntryPoint() {
	config := loadConfig()
	cfAuth := internal.CloudflareAuth{
		CloudflareZoneId:   config.CloudflareZoneID,
		CloudflareApiToken: config.CloudflareAPIToken,
	}

	identifiers := acme.DomainIDs(config.Domains...)
	// identifiers = append(identifiers, acme.IPIDs(strings.Fields(*ipaddr)...)...)
	if len(identifiers) == 0 {
		log.Fatal("at least one domain or IP addr identifier is required")
	}

	// Duration of the whole run.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create and register a new account.
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		cleanUp(cfAuth, ctx)
		log.Fatal(err)
	}
	cl := &acme.Client{Key: akey, DirectoryURL: config.Directory}
	a := &acme.Account{Contact: []string{config.RegInfo}}

	if _, err := cl.Register(ctx, a, acme.AcceptTOS); err != nil {
		cleanUp(cfAuth, ctx)
		log.Fatalf("Register: %v", err)
	}

	p := &internal.Prober{
		Client:   cl,
		ChalType: "dns-01",

		CfAuth: cfAuth,
	}

	certKey, curl := p.RunOrder(ctx, identifiers)
	afterOrderCert(config, certKey, curl)
	cleanUp(cfAuth, ctx)

	if config.AfterSetupScript != "" {
		_, err = os.Stat(config.AfterSetupScript)
		if os.IsNotExist(err) {
			fmt.Printf("afterSetup not exist: %v", config.AfterSetupScript)
			return
		}

		fmt.Println("Running afterSetup!!")
		timeout := time.Now().Add(time.Second * 30)
		for time.Now().Before(timeout) {
			_ = afterSetup(config.AfterSetupScript, ctx)
		}
	}
}

func cleanUp(cfAuth internal.CloudflareAuth, ctx context.Context) {
	// cleanUp or AllThingsDone
	fmt.Println("Running cleanUp!!")
	cfAuth.DelChallengeRecord(ctx)
}

func afterOrderCert(config Config, certKey crypto.Signer, curl string) {
	fmt.Println("Running afterOrderCert!!")
	// saveFile("ssl.csr", csr)
	prikey, _ := internal.EncodeKey(certKey, certKey.Public())
	internal.SaveFile(config.SavingKeyPath, []byte(prikey))
	// saveFile("ssl.pub.key", []byte(pubkey))
	err := internal.DownloadFile(config.SavingCerPath, curl)
	if err != nil {
		log.Fatalf("download file err: %v", err)
	}
}

func afterSetup(scriptPath string, ctx context.Context) error {
	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v", scriptPath, err)
	}

	return nil
}
