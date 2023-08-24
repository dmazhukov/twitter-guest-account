// Package xacc is for working with TwiXer accounts.
//
// See:
// - https://blog.nest.moe/posts/how-to-crawl-twitter-with-android
// - https://github.com/zedeus/nitter/issues/983#issuecomment-1681199357
package xacc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
)

const (
	// const TW_CONSUMER_KEY = '3nVuSoBZnx6U4vzUxf5w'
	// const TW_CONSUMER_SECRET = 'Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys'
	twConsumerKey    = "3nVuSoBZnx6U4vzUxf5w"
	twConsumerSecret = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys"

	defaultBearerToken = "bearer AAAAAAAAAAAAAAAAAAAAAFXzAwAAAAAAMHCxpeSDG1gLNLghVe8d74hl6k4%3DRUMF4xAQLsbeBhTSRrCiQpJtxoGWeyHrDb5te2jpGskWDFW82F"
)

var (
	twAndroidBasicToken = func() string {
		// const TW_ANDROID_BASIC_TOKEN = `Basic ${btoa(TW_CONSUMER_KEY+':'+TW_CONSUMER_SECRET)}`
		return "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(twConsumerKey+":"+twConsumerSecret),
		)
	}()

	errHTTPStatus  = errors.New("xacc: unexpected http status")
	errNotPrepared = errors.New("xacc: session not prepared for account creation")
	errSubtask     = errors.New("xacc: subtask failure")

	ErrMaybeRateLimited = errors.New("xacc: missing subtask 'OpenAccount', likely rate limited")
)

type GuestCreator struct {
	log *slog.Logger

	bearerToken string
	sessionID   uint32
}

func (ctor *GuestCreator) Session() *GuestCreationSession {
	id := atomic.AddUint32(&ctor.sessionID, 1)

	return &GuestCreationSession{
		ctor: ctor,
		log:  ctor.log.With("id", id),
	}
}

func NewGuestCreator(ctx context.Context, logger *slog.Logger, fetchBearerToken bool) (*GuestCreator, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ctor := &GuestCreator{
		log:         logger.WithGroup("xacc"),
		bearerToken: defaultBearerToken,
	}
	if fetchBearerToken {
		if err := ctor.getBearerToken(ctx); err != nil {
			ctor.log.Error("getBearerToken", "err", err)
			return nil, err
		}
	}

	return ctor, nil
}

func (ctor *GuestCreator) getBearerToken(ctx context.Context) error {
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

	ctor.bearerToken = ""

	ctor.log.Debug("Get bearer token", "basic_token", twAndroidBasicToken)

	b, err := doHttpPost(
		ctx,
		ctor.log,
		"https://api.twitter.com/oauth2/token",
		"grant_type=client_credentials",
		map[string]string{
			"Authorization": twAndroidBasicToken,
			"Content-Type":  "application/x-www-form-urlencoded",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to dispatch bearer token POST: %w", err)
	}

	type tokenResponse struct {
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return fmt.Errorf("failed to parse bearer token response body: %w", err)
	}

	ctor.bearerToken = strings.Join([]string{token.TokenType, token.AccessToken}, " ")

	return nil
}

type GuestCreationSession struct {
	ctor *GuestCreator

	log *slog.Logger

	guestToken  string
	flowHeaders map[string]string
	flowToken   string
	prepared    bool
}

func (sess *GuestCreationSession) Reset() {
	sess.guestToken = ""
	sess.flowHeaders = nil
	sess.flowToken = ""
	sess.prepared = false
}

func (sess *GuestCreationSession) PrepareCreate(ctx context.Context) error {
	wasCanceled := func() error {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			sess.log.Error("context canceled", "err", err)
			return err
		default:
		}
		return nil
	}

	if sess.guestToken == "" {
		if err := sess.getGuestToken(ctx); err != nil {
			sess.log.Error("getGuestToken", "err", err)
			return err
		}
		sess.getFlowHeaders()
	}

	if err := wasCanceled(); err != nil {
		return err
	}

	if sess.flowToken == "" {
		if err := sess.getFlowToken(ctx); err != nil {
			slog.Error("getFlowToken", "err", err)
			return err
		}
	}

	sess.prepared = true

	return nil
}

func (sess *GuestCreationSession) CreateAccount(ctx context.Context) (string, error) {
	if !sess.prepared {
		return "", errNotPrepared
	}

	acc, err := sess.getSubtaskOpenAccount(ctx)
	if err != nil {
		slog.Error("getSubtaskOpenAccount", "err", err)
		return "", err
	}

	sess.Reset()

	return acc, nil
}

func (sess *GuestCreationSession) getGuestToken(ctx context.Context) error {
	// const guest_token = (await axios("https://api.twitter.com/1.1/guest/activate.json", {
	//     headers: {
	//         Authorization: bearer_token
	//     },
	//     method: "post"
	// })).data.guest_token

	sess.guestToken = ""

	bearerToken := sess.ctor.bearerToken
	sess.log.Debug("Get guest token", "bearer_token", bearerToken)

	b, err := doHttpPost(
		ctx,
		sess.log,
		"https://api.twitter.com/1.1/guest/activate.json",
		"",
		map[string]string{
			"Authorization": bearerToken,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to dispatch guest token POST: %w", err)
	}

	type tokenResponse struct {
		GuestToken string `json:"guest_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return fmt.Errorf("failed to parse guest token response body: %w", err)
	}

	sess.guestToken = token.GuestToken

	return nil
}

func (sess *GuestCreationSession) getFlowHeaders() {
	// This is incredibly fragile, and would be what I would target if I were
	// on the other end trying to break this, without collateral damage.

	sess.flowHeaders = map[string]string{
		"Authorization":            sess.ctor.bearerToken,
		"Content-Type":             "application/json",
		"User-Agent":               "TwitterAndroid/9.95.0-release.0 (29950000-r-0) ONEPLUS+A3010/9 (OnePlus;ONEPLUS+A3010;OnePlus;OnePlus3;0;;1;2016)",
		"X-Twitter-API-Version":    "5",
		"X-Twitter-Client":         "TwitterAndroid",
		"X-Twitter-Client-Version": "9.95.0-release.0",
		"OS-Version":               "28",
		"System-User-Agent":        "Dalvik/2.1.0 (Linux; U; Android 9; ONEPLUS A3010 Build/PKQ1.181203.001)",
		"X-Twitter-Active-User":    "yes",
		"X-Guest-Token":            sess.guestToken,
	}
}

func (sess *GuestCreationSession) getFlowToken(ctx context.Context) error {
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

	sess.flowToken = ""

	sess.log.Debug("Get flow token")

	b, err := doHttpPost(
		ctx,
		sess.log,
		"https://api.twitter.com/1.1/onboarding/task.json?flow_name=welcome&api_version=1&known_device_token=&sim_country_code=us",
		`{"flow_token":null,"input_flow_data":{"country_code":null,"flow_context":{"start_location":{"location":"splash_screen"}},"requested_variant":null,"target_user_id":0},"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}`,
		sess.flowHeaders,
	)
	if err != nil {
		return fmt.Errorf("failed to dispatch flow token POST: %w", err)
	}

	type tokenResponse struct {
		FlowToken string `json:"flow_token"`
	}

	var token tokenResponse
	if err = json.Unmarshal(b, &token); err != nil {
		return fmt.Errorf("failed to parse flow token response body: %w", err)
	}

	sess.flowToken = token.FlowToken

	return nil
}

func (sess *GuestCreationSession) getSubtaskOpenAccount(ctx context.Context) (string, error) {
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

	sess.log.Debug("Get subtasks")

	b, err := doHttpPost(
		ctx,
		sess.log,
		"https://api.twitter.com/1.1/onboarding/task.json",
		`{"flow_token":"`+sess.flowToken+`","subtask_inputs":[{"open_link":{"link":"next_link"},"subtask_id":"NextTaskOpenLink"}],"subtask_versions":{"generic_urt":3,"standard":1,"open_home_timeline":1,"app_locale_update":1,"enter_date":1,"email_verification":3,"enter_password":5,"enter_text":5,"one_tap":2,"cta":7,"single_sign_on":1,"fetch_persisted_data":1,"enter_username":3,"web_modal":2,"fetch_temporary_password":1,"menu_dialog":1,"sign_up_review":5,"interest_picker":4,"user_recommendations_urt":3,"in_app_notification":1,"sign_up":2,"typeahead_search":1,"user_recommendations_list":4,"cta_inline":1,"contacts_live_sync_permission_prompt":3,"choice_selection":5,"js_instrumentation":1,"alert_dialog_suppress_client_events":1,"privacy_options":1,"topics_selector":1,"wait_spinner":3,"tweet_selection_urt":1,"end_flow":1,"settings_list":7,"open_external_link":1,"phone_verification":5,"security_key":3,"select_banner":2,"upload_media":1,"web":2,"alert_dialog":1,"open_account":2,"action_list":2,"enter_phone":2,"open_link":1,"show_code":1,"update_users":1,"check_logged_in_account":1,"enter_email":2,"select_avatar":4,"location_permission_prompt":2,"notifications_permission_prompt":4}}`,
		sess.flowHeaders,
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

	return "", ErrMaybeRateLimited
}

func doHttpPost(
	ctx context.Context,
	log *slog.Logger,
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

	log.Debug("HTTP POST - request", "uri", uri)

	// If people want to extend this to support dynaically picking a HTTP
	// proxy, then instead of using DefaultClient, instantiate a Transport,
	// with a different `Proxy` function.
	//
	// This is not required to get this to honor `HTTP_PROXY`, `HTTPS_PROXY`,
	// but all the public ones are rate-limited anyway.
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

	log.Debug("HTTP POST - response", "body", string(b))

	return b, nil
}
