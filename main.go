// Attempt to mimic a twitter Android client to create a guest account,
// so that it is possible to view twitter posts without creating a real
// account.
//
// See:
// - https://blog.nest.moe/posts/how-to-crawl-twitter-with-android
// - https://github.com/zedeus/nitter/issues/983#issuecomment-1681199357
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// const TW_CONSUMER_KEY = '3nVuSoBZnx6U4vzUxf5w'
	// const TW_CONSUMER_SECRET = 'Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys'
	twConsumerKey    = "3nVuSoBZnx6U4vzUxf5w"
	twConsumerSecret = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys"

	defaultBearerToken = "bearer AAAAAAAAAAAAAAAAAAAAAFXzAwAAAAAAMHCxpeSDG1gLNLghVe8d74hl6k4%3DRUMF4xAQLsbeBhTSRrCiQpJtxoGWeyHrDb5te2jpGskWDFW82F"
)

var twAndroidBasicToken = func() string {
	// const TW_ANDROID_BASIC_TOKEN = `Basic ${btoa(TW_CONSUMER_KEY+':'+TW_CONSUMER_SECRET)}`
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(twConsumerKey+":"+twConsumerSecret),
	)
}()

var (
	errHTTPStatus = errors.New("unexpected http status")
	errSubtask    = errors.New("subtask failure")
)

func doFlowPost(
	ctx context.Context,
	uri string,
	body string,
	headers map[string]string,
) ([]byte, error) {
	postBody := bytes.NewBufferString(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, postBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow request: %w", err)
	}
	req.Header.Set("User-Agent", "") // Do not send unless caller explicitly sets.
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	slog.Debug("HTTP POST - request", "uri", uri)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to dispatch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d (%s)", errHTTPStatus, resp.StatusCode, resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read flow response body: %w", err)
	}

	slog.Debug("HTTP POST - response", "body", string(b))

	return b, nil
}

func getBearerToken(ctx context.Context) (string, error) {
	// const getBearerToken = async () => {
	//     const tmpTokenResponse = await axios('https://api.twitter.com/oauth2/token', {
	//         headers: {
	//             Authorization: TW_ANDROID_BASIC_TOKEN,
	//             'Content-Type': 'application/x-www-form-urlencoded'
	//         },
	//         method: 'post',
	//         data: 'grant_type=client_credentials'
	//     })
	//     return Object.values(tmpTokenResponse.data).join(" ")
	// }
	// // The bearer token is immutable
	// // Bearer AAAAAAAAAAAAAAAAAAAAAFXzAwAAAAAAMHCxpeSDG1gLNLghVe8d74hl6k4%3DRUMF4xAQLsbeBhTSRrCiQpJtxoGWeyHrDb5te2jpGskWDFW82F
	// const bearer_token = await getBearerToken()

	slog.Debug("Get bearer token", "basic_token", twAndroidBasicToken)

	b, err := doFlowPost(
		ctx,
		"https://api.twitter.com/oauth2/token",
		"grant_type=client_credentials",
		map[string]string{
			"Authorization": twAndroidBasicToken,
			"Content-Type":  "application/x-www-form-urlencoded",
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to dispatch bearer token POST: %w", err)
	}

	type tokenResponse struct {
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return "", fmt.Errorf("failed to parse bearer token response body: %w", err)
	}

	return strings.Join([]string{token.TokenType, token.AccessToken}, " "), nil
}

func getGuestToken(ctx context.Context, bearerToken string) (string, error) {
	// const guest_token = (await axios("https://api.twitter.com/1.1/guest/activate.json", {
	//     headers: {
	//         Authorization: bearer_token
	//     },
	//     method: "post"
	// })).data.guest_token

	slog.Debug("Get guest token", "bearer_token", bearerToken)

	b, err := doFlowPost(
		ctx,
		"https://api.twitter.com/1.1/guest/activate.json",
		"",
		map[string]string{
			"Authorization": bearerToken,
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to dispatch guest token POST: %w", err)
	}

	type tokenResponse struct {
		GuestToken string `json:"guest_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return "", fmt.Errorf("failed to parse guest token response body: %w", err)
	}

	return token.GuestToken, nil
}

func getFlowHeaders(bearerToken, guestToken string) map[string]string {
	// This is incredibly fragile, and would be what I would target if I were
	// on the other end trying to break this, without collateral damage.

	return map[string]string{
		"Authorization":            bearerToken,
		"Content-Type":             "application/json",
		"User-Agent":               "TwitterAndroid/9.95.0-release.0 (29950000-r-0) ONEPLUS+A3010/9 (OnePlus;ONEPLUS+A3010;OnePlus;OnePlus3;0;;1;2016)",
		"X-Twitter-API-Version":    "5",
		"X-Twitter-Client":         "TwitterAndroid",
		"X-Twitter-Client-Version": "9.95.0-release.0",
		"OS-Version":               "28",
		"System-User-Agent":        "Dalvik/2.1.0 (Linux; U; Android 9; ONEPLUS A3010 Build/PKQ1.181203.001)",
		"X-Twitter-Active-User":    "yes",
		"X-Guest-Token":            guestToken,
	}
}

func getFlowToken(ctx context.Context, flowHeaders map[string]string) (string, error) {
	// const flow_token = (await axios('https://api.twitter.com/1.1/onboarding/task.json?flow_name=welcome&api_version=1&known_device_token=&sim_country_code=us', {
	//     headers: {
	//         Authorization: bearer_token,
	//         'Content-Type': 'application/json',
	//         'User-Agent': 'TwitterAndroid/9.95.0-release.0 (29950000-r-0) ONEPLUS+A3010/9 (OnePlus;ONEPLUS+A3010;OnePlus;OnePlus3;0;;1;2016)',
	//         'X-Twitter-API-Version': 5,
	//         'X-Twitter-Client': 'TwitterAndroid',
	//         'X-Twitter-Client-Version': '9.95.0-release.0',
	//         'OS-Version': '28',
	//         'System-User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ONEPLUS A3010 Build/PKQ1.181203.001)',
	//         'X-Twitter-Active-User': 'yes',
	//         'X-Guest-Token': guest_token
	//     },
	//     method: 'post',
	//     data: '{"flow_token":null,"input_flow_data":{"country_code":null,"flow_context":{"start_location":{"location":"splash_screen"}},"requested_variant":null,"target_user_id":0},"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}'
	// })).data.flow_token

	slog.Debug("Get flow token")

	b, err := doFlowPost(
		ctx,
		"https://api.twitter.com/1.1/onboarding/task.json?flow_name=welcome&api_version=1&known_device_token=&sim_country_code=us",
		`{"flow_token":null,"input_flow_data":{"country_code":null,"flow_context":{"start_location":{"location":"splash_screen"}},"requested_variant":null,"target_user_id":0},"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}`,
		flowHeaders,
	)
	if err != nil {
		return "", fmt.Errorf("failed to dispatch flow token POST: %w", err)
	}

	type tokenResponse struct {
		FlowToken string `json:"flow_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return "", fmt.Errorf("failed to parse flow token response body: %w", err)
	}

	return token.FlowToken, nil
}

func getSubtaskOpenAccount(ctx context.Context, flowHeaders map[string]string, flowToken string, maxRetries int) (string, error) {
	// const subtasks = (await axios('https://api.twitter.com/1.1/onboarding/task.json', {
	//     headers: {
	//         Authorization: bearer_token,
	//         'Content-Type': 'application/json',
	//         'User-Agent': 'TwitterAndroid/9.95.0-release.0 (29950000-r-0) ONEPLUS+A3010/9 (OnePlus;ONEPLUS+A3010;OnePlus;OnePlus3;0;;1;2016)',
	//         'X-Twitter-API-Version': 5,
	//         'X-Twitter-Client': 'TwitterAndroid',
	//         'X-Twitter-Client-Version': '9.95.0-release.0',
	//         'OS-Version': '28',
	//         'System-User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ONEPLUS A3010 Build/PKQ1.181203.001)',
	//         'X-Twitter-Active-User': 'yes',
	//         'X-Guest-Token': guest_token
	//     },
	//     method: 'post',
	//     data: '{"flow_token":"' + flow_token + '","subtask_inputs":[{"open_link":{"link":"next_link"},"subtask_id":"NextTaskOpenLink"}],"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}'
	// })).data.subtasks
	//
	// const account = subtasks.find(task => task.subtask_id === 'OpenAccount')?.open_account
	// console.log(account)

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

	for i, delay := 0, baseDelay; i < maxRetries; i++ {
		slog.Debug("Subtasks next_link rate limit avoidance delay", "delay", delay)

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(delay):
		}
		delay = min(maxDelay, delay*2)

		slog.Debug("Get subtasks")

		b, err := doFlowPost(
			ctx,
			"https://api.twitter.com/1.1/onboarding/task.json",
			`{"flow_token":"`+flowToken+`","subtask_inputs":[{"open_link":{"link":"next_link"},"subtask_id":"NextTaskOpenLink"}],"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}`,
			flowHeaders,
		)
		if err != nil {
			return "", fmt.Errorf("failed to dispatch subtask POST: %w", err)
		}

		type subtask struct {
			SubtaskID   string          `json:"subtask_id"`
			OpenAccount json.RawMessage `json:"open_account,omitempty"`
		}

		type subtaskResponse struct {
			Status   string    `json:"status"`
			Subtasks []subtask `json:"subtasks"`
		}

		var subtasks subtaskResponse
		if err = json.Unmarshal(b, &subtasks); err != nil {
			return "", fmt.Errorf("failed to parse subtask response body: %w", err)
		}

		if subtasks.Status != "success" {
			return "", fmt.Errorf("%w: '%s'", errSubtask, subtasks.Status)
		}

		for _, v := range subtasks.Subtasks {
			if v.SubtaskID == "OpenAccount" {
				return string(v.OpenAccount), nil
			}
		}
	}

	return "", fmt.Errorf("%w: exhausted OpenAccount retries (rate limited?)", errSubtask)
}

func createGuestAccount(ctx context.Context, fetchBearerToken bool, maxRetries int) (string, error) {
	bearerToken := defaultBearerToken
	if fetchBearerToken {
		// Retrieve a bearer token.
		var err error
		bearerToken, err = getBearerToken(ctx)
		if err != nil {
			slog.Error("getBearerToken", "err", err)
			return "", err
		}
	}

	// Retrieve a guest token.
	guestToken, err := getGuestToken(ctx, bearerToken)
	if err != nil {
		slog.Error("getGuestToken", "err", err)
		return "", err
	}

	// Construct the common headers for the rest of the onboarding flow.
	flowHdrs := getFlowHeaders(bearerToken, guestToken)

	// Get a flow token.
	flowToken, err := getFlowToken(ctx, flowHdrs)
	if err != nil {
		slog.Error("getFlowToken", "err", err)
		return "", err
	}

	// Attempt to actually open the guest account.
	guestAccount, err := getSubtaskOpenAccount(ctx, flowHdrs, flowToken, maxRetries)
	if err != nil {
		slog.Error("getSubtaskOpenAccount", "err", err)
		return "", err
	}

	return guestAccount, nil
}

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

	var f *os.File
	writeStrToF := func(s string) {
		if f == nil {
			return
		}
		if _, err := f.WriteString(s); err != nil {
			slog.Error("failed to write to file", "err", err)
		}
	}

	if fn := *outputPath; fn != "" {
		var err error
		if _, err = os.Stat(fn); !errors.Is(err, os.ErrNotExist) {
			slog.Error("stat output file (probably exists already)", "err", err)
			os.Exit(1)
		}
		f, err = os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			slog.Error("open output file", "err", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	writeStrToF("[")

	for i := uint(0); i < *numAccounts; i++ {
		guestAccount, err := createGuestAccount(ctx, *fetchBearerToken, int(*numAttempts))
		if err != nil {
			slog.Error("failed to create guest account", "err", err)
			break
		}

		slog.Info("created guest account", "guest_account", guestAccount)

		fmt.Printf("%s\n", guestAccount)

		s := guestAccount
		if i > 0 {
			s = "," + s
		}
		writeStrToF(s)
	}

	writeStrToF("]")
}
