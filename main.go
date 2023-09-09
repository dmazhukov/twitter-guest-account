// Attempt to mimic a twitter Android client to create a guest account,
// so that it is possible to view twitter posts without creating a real
// account.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gitlab.com/yawning/twitter-guest-account/xacc"
)

func main() {
	ctx := context.Background()

	fetchBearerToken := flag.Bool("fetch-bearer-token", false, "fetch a new bearer token")
	numAccounts := flag.Uint("num-accounts", 1, "number of accounts to create")
	numAttempts := flag.Uint("num-attempts", 3, "number of attempts before giving up")
	outputPath := flag.String("output-path", "guest_accounts.json", "output file")
	debugLogging := flag.Bool("debug-logging", false, "debug logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *debugLogging {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	ctor, err := xacc.NewGuestCreator(ctx, logger, *fetchBearerToken)
	if err != nil {
		slog.Error("failed to initialze account creator", "err", err)
		os.Exit(1)
	}

	var f *os.File
	writeStrToF := func(s string) {
		if f == nil {
			return
		}
		if _, err := f.WriteString(s); err != nil {
			slog.Error("failed to write to file", "err", err)
		}
	}

	fileExists := false
	if fn := *outputPath; fn != "" {
		var err error
		if _, err = os.Stat(fn); !errors.Is(err, os.ErrNotExist) {
			fileExists = true
			// slog.Error("stat output file (probably exists already)", "err", err)
			// os.Exit(1)
		}
		f, err = os.OpenFile(fn, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			slog.Error("open output file", "err", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	if !fileExists {
		writeStrToF("[")
	} else {
		f.Seek(-1, 2)
	}

	maxRetries := int(*numAttempts)
	for i := uint(0); i < *numAccounts; i++ {
		// This will honor the `HTTP_PROXY`/`HTTPS_PROXY` environment
		// variables, without explicit configuration.
		session := ctor.Session(nil)
		if err = session.PrepareCreate(ctx); err != nil {
			break
		}

		// https://github.com/zedeus/nitter/issues/983#issuecomment-1685698147
		//
		// Also for account creation I can't workout whether there is some
		// fundamental delay in generation of the oauth guest accounts requiring
		// a second call to the open_link to get an account open or whether
		// it's the rotation of IP that does it but you can go through patches
		// of accounts opening right away and sometimes requiring 3+ calls for
		// it to happen. For your mass creation did you just fire off a bunch
		// all at once and take what worked or did you keep retrying? Ive
		// been manually opening up accounts with postman to try and figure
		// out how the flow.json endpoint works as I'll need to do this every
		// month it seems.

		// https://github.com/zedeus/nitter/issues/983#issuecomment-1688353795
		//
		// Sometimes it appears there is a delay in the creation of the account
		// so you need to wait a few seconds/minutes and then it will create
		// if you call the next_link again.
		//
		// As mentioned it can also be an IP restriction issue, so rotating IP
		// will cause the account to create. For all the fun, it can be a
		// combination of both!

		const (
			baseDelay = 5 * time.Second
			maxDelay  = 3 * time.Minute
		)

		var guestAccount string
		for i, delay := 0, baseDelay; i < maxRetries; i++ {
			slog.Debug("Subtasks next_link rate limit avoidance delay", "delay", delay)
			<-time.After(delay)

			delay = min(maxDelay, delay*2)

			guestAccount, err = session.CreateAccount(ctx)
			if err == nil {
				break
			}
		}
		if guestAccount == "" {
			slog.Warn("failed to create account after max retries, giving up")
			break
		}

		slog.Info("created guest account", "guest_account", guestAccount)

		fmt.Printf("%s\n", guestAccount)

		s := guestAccount
		if i > 0 || fileExists {
			s = "," + s
		}

		writeStrToF(s)
	}

	writeStrToF("]")
}
