package test

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	m1STokenImage = "sing-openconnect-stoken:837e843"
	m1STokenV2    = "http://127.0.0.1/securid/ctf?ctfData=258491750817210752367175001073261277346642631755724762324173166222072472716737543"
	m1STokenV3    = "http://127.0.0.1/securid/ctf?ctfData=AwEBWoDfCnTYFHKM8RvGCXEbSiReGdGgA88EDrIP6EhAe8tzPkIGiAaXXtInt6UHsgM1NFmwuTVjOlJXIpNXxmj7Iud0hfL2kLmIdPgRiS6jP%2FO8q9Fcpwo%2F8tLukZRoIU7gdFjpSl3teO%2FMWlr9rJBZtkTW4q0mAehJ1tl4l0vGjcDycwmIgyzeods7F43ljVETNZjlHkDTudosNSvmS%2Bl643vFrM6NGT%2BHLrlCX0igfo5i4yaUKwDDS4AiAEq%2Bpp0dv8ZzkpZIEJikRzeWaxpfml%2BmsakJ%2BYAVFcfBoR2%2BLzr1%2Flp7mX%2BwMw4TFDZ4hS88BMY3P7uV9%2BGNz08Euaru779p4XDde0JxrPGPuGjWxUBt%2BN5aUjJkcXvAtswhfirK"
	m1STokenV4    = "com.rsa.securid://ctf?ctfData=BAABaKfqKwgEkWDGEgaxp2ZGloQ7dDw2A8PglNlhP8qCBhtop%2BorCASRYMYSBrGnZkaWhDt0PDYDw%2BCU2WE%2FyoIGGznAfd6pVLcjsDtpKoG5APTUrXL51Bdnf%2FCDvZanmNEGhzDCbsDsFTFyLgKzdht0X1tKt23tFwP%2FDYg9xDS1HvS8Jy3QfT04PFNm%2BdCUUZyMIoTzdFT01msNHtrRxePWU7cB32CE48U%2BKlbW4hPyhphJhkg5qxUA38cD05J1s44hI3FTjaq%2FAhAKAQWsDy7TZE6qtU5f6cYIzdr5PKILhTyCeXRxiYuLinAkXEHWm%2F%2FrFKyroQpn%2FVYAA3NLS59HWBQwWyS2kzhtlzJh%2BI25IMhdhLvVdXdjuNzRxkwjc74z"
)

type m1STokenFixture struct {
	name     string
	token    string
	pin      string
	password string
	deviceID string
}

type m1STokenSubmission struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		Code string `xml:"password"`
	} `xml:"auth"`
}

func TestM1AnyConnectSTokenInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	_, err := dockerOutput(ctx, "build", "--pull=false", "--tag", m1STokenImage, filepath.Join("testdata", "stoken"))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []m1STokenFixture{
		{name: "ctf-v2", token: m1STokenV2, pin: "9999"},
		{
			name:     "ctf-v3-password-device",
			token:    m1STokenV3,
			pin:      "1234",
			password: "Correct_horse!battery&staple",
			deviceID: "a01c4380-fc01-4df0-b113-7fb98ec74694",
		},
		{
			name:     "ctf-v4-device",
			token:    m1STokenV4,
			pin:      "1234",
			deviceID: "d82c-467c-56fb-2058-edf8-add6",
		},
	}
	for i := range fixtures {
		fixture := fixtures[i]
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			runM1STokenConsumer(t, ctx, fixture)
		})
	}
}

func runM1STokenConsumer(t *testing.T, parentContext context.Context, fixture m1STokenFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parentContext, 45*time.Second)
	t.Cleanup(cancel)
	consumerErrors := make(chan error, 4)
	accepted := make(chan struct{}, 1)
	var authenticationAccess sync.Mutex
	var authenticationRound int
	var challengeUnixTime int64
	var firstCode string
	consumer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			reportM1STokenConsumerError(consumerErrors, E.Cause(err, "read stoken consumer request"))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/" && strings.Contains(string(body), `type="init"`):
			authenticationAccess.Lock()
			challengeUnixTime = time.Now().Unix()
			authenticationAccess.Unlock()
			writer.Header().Set("Content-Type", "application/xml")
			_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main"><message>Enter the RSA SecurID tokencode.</message>
<form method="post" action="/auth"><input type="password" name="password" label="Passcode:" /></form>
</auth></config-auth>`)
			if err != nil {
				reportM1STokenConsumerError(consumerErrors, E.Cause(err, "write stoken challenge"))
			}
		case request.Method == http.MethodPost && request.URL.Path == "/auth":
			var submission m1STokenSubmission
			err = xml.Unmarshal(body, &submission)
			if err != nil {
				reportM1STokenConsumerError(consumerErrors, E.Cause(err, "parse stoken authentication reply"))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			if submission.Type != "auth-reply" {
				reportM1STokenConsumerError(consumerErrors, E.New("stoken consumer received unexpected reply type: ", submission.Type))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			authenticationAccess.Lock()
			authenticationRound++
			currentRound := authenticationRound
			if currentRound == 1 {
				firstCode = submission.Auth.Code
			}
			initialCode := firstCode
			initialUnixTime := challengeUnixTime
			authenticationAccess.Unlock()
			switch currentRound {
			case 1:
				writer.Header().Set("Content-Type", "application/xml")
				_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="challenge"><message>Please enter the next tokencode.</message>
<form method="post" action="/auth"><input type="password" name="password" label="Next tokencode:" /></form>
</auth></config-auth>`)
				if err != nil {
					reportM1STokenConsumerError(consumerErrors, E.Cause(err, "write stoken next-tokencode challenge"))
				}
				return
			case 2:
				err = validateM1STokenPairWithCConsumer(ctx, fixture, initialUnixTime, initialCode, submission.Auth.Code)
				if err != nil {
					reportM1STokenConsumerError(consumerErrors, err)
					writer.WriteHeader(http.StatusUnauthorized)
					return
				}
			default:
				reportM1STokenConsumerError(consumerErrors, E.New("stoken consumer received unexpected authentication round: ", currentRound))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/xml")
			_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>stoken-session-cookie</session-token><auth id="success" />
</config-auth>`)
			if err != nil {
				reportM1STokenConsumerError(consumerErrors, E.Cause(err, "write stoken authentication success"))
				return
			}
			accepted <- struct{}{}
		case request.Method == http.MethodConnect:
			writer.Header().Set("X-CSTP-MTU", "1400")
			writer.Header().Set("X-CSTP-Address", "192.0.2.20")
			writer.Header().Set("X-CSTP-Netmask", "255.255.255.0")
			writer.Header().Set("X-CSTP-Rekey-Method", "none")
			writer.WriteHeader(http.StatusOK)
		default:
			reportM1STokenConsumerError(consumerErrors, E.New("stoken consumer received unexpected request: ", request.Method, " ", request.URL.Path))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(consumer.Close)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  strings.TrimPrefix(consumer.URL, "https://"),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Token: &openconnect.TokenOptions{
			Mode:     openconnect.TokenModeSToken,
			Secret:   fixture.token,
			PIN:      fixture.pin,
			Password: fixture.password,
			DeviceID: fixture.deviceID,
		},
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect stoken client"))
	}
	authFormUpdated := client.AuthChallengeUpdated()
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close AnyConnect stoken client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect stoken client"))
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for independent libstoken consumer"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case <-authFormUpdated:
		t.Fatalf("automatic stoken next-tokencode flow published a user form: %#v", client.PendingAuthChallenge())
	case <-accepted:
	}
	if form := client.PendingAuthChallenge(); form != nil {
		t.Fatalf("automatic stoken unexpectedly prompted: %#v", form)
	}
}

func validateM1STokenPairWithCConsumer(
	ctx context.Context,
	fixture m1STokenFixture,
	challengeUnixTime int64,
	initialCode string,
	nextCode string,
) error {
	showArguments := []string{
		"run", "--rm", m1STokenImage,
		"show",
		"--token", fixture.token,
		"--pin", fixture.pin,
	}
	if fixture.password != "" {
		showArguments = append(showArguments, "--password", fixture.password)
	}
	if fixture.deviceID != "" {
		showArguments = append(showArguments, "--devid", fixture.deviceID)
	}
	showOutput, err := dockerOutput(ctx, showArguments...)
	if err != nil {
		return E.Cause(err, "read independent libstoken token period")
	}
	var period int64
	for _, line := range strings.Split(showOutput, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "Seconds per tokencode") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		period, err = strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err != nil {
			return E.Cause(err, "parse independent libstoken token period")
		}
		break
	}
	if period <= 0 {
		return E.New("independent libstoken did not report a positive token period: ", showOutput)
	}
	var oracleErrors []error
	for _, offset := range []int64{-period, 0, period} {
		generationUnixTime := challengeUnixTime + offset
		arguments := []string{
			"run", "--rm", m1STokenImage,
			"tokencode",
			"--token", fixture.token,
			"--use-time", strconv.FormatInt(generationUnixTime, 10),
			"--pin", fixture.pin,
		}
		if fixture.password != "" {
			arguments = append(arguments, "--password", fixture.password)
		}
		if fixture.deviceID != "" {
			arguments = append(arguments, "--devid", fixture.deviceID)
		}
		output, oracleErr := dockerOutput(ctx, arguments...)
		if oracleErr != nil {
			oracleErrors = append(oracleErrors, oracleErr)
			continue
		}
		if strings.TrimSpace(output) != initialCode {
			continue
		}
		for i := range arguments {
			if arguments[i] == "--use-time" && i+1 < len(arguments) {
				arguments[i+1] = strconv.FormatInt(generationUnixTime+period, 10)
				break
			}
		}
		output, oracleErr = dockerOutput(ctx, arguments...)
		if oracleErr != nil {
			oracleErrors = append(oracleErrors, oracleErr)
			continue
		}
		if strings.TrimSpace(output) == nextCode {
			return nil
		}
	}
	if len(oracleErrors) > 0 {
		return E.Cause(E.Errors(oracleErrors...), "run independent libstoken consumer")
	}
	return E.New("independent libstoken consumer rejected current/next tokencode pair: ", initialCode, "/", nextCode)
}

func reportM1STokenConsumerError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}
