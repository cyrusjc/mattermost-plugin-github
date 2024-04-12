package plugin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v41/github"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/mattermost/mattermost/server/public/pluginapi"

	"github.com/mattermost/mattermost-plugin-github/server/testutils"
)

type panicHandler struct {
}

func (ph panicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	panic("bad handler")
}

func TestWithRecovery(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			require.Fail(t, "got panic")
		}
	}()

	p := NewPlugin()
	api := &plugintest.API{}
	api.On("LogWarn",
		"Recovered from a panic",
		"url", "http://random",
		"error", "bad handler",
		"stack", mock.Anything)
	p.SetAPI(api)
	p.client = pluginapi.NewClient(p.API, p.Driver)

	ph := panicHandler{}
	handler := p.withRecovery(ph)

	req := httptest.NewRequest(http.MethodGet, "http://random", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.Body != nil {
		defer resp.Body.Close()
		_, err := io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
	}
}

func TestPlugin_ServeHTTP(t *testing.T) {
	httpTestJSON := testutils.HTTPTest{
		T:       t,
		Encoder: testutils.EncodeJSON,
	}

	httpTestString := testutils.HTTPTest{
		T:       t,
		Encoder: testutils.EncodeString,
	}

	for name, test := range map[string]struct {
		httpTest         testutils.HTTPTest
		request          testutils.Request
		expectedResponse testutils.ExpectedResponse
		userID           string
	}{
		"unauthorized test json": {
			httpTest: httpTestJSON,
			request: testutils.Request{
				Method: http.MethodPost,
				URL:    "/api/v1/todo",
				Body:   nil,
			},
			expectedResponse: testutils.ExpectedResponse{
				StatusCode:   http.StatusUnauthorized,
				ResponseType: testutils.ContentTypeJSON,
				Body:         APIErrorResponse{ID: "", Message: "Not authorized.", StatusCode: http.StatusUnauthorized},
			},
			userID: "",
		}, "unauthorized test http": {
			httpTest: httpTestString,
			request: testutils.Request{
				Method: http.MethodGet,
				URL:    "/api/v1/lhs-content",
				Body:   nil,
			},
			expectedResponse: testutils.ExpectedResponse{
				StatusCode:   http.StatusUnauthorized,
				ResponseType: testutils.ContentTypePlain,
				Body:         "Not authorized\n",
			},
			userID: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin()
			p.setConfiguration(
				&Configuration{
					GitHubOrg:               "mockOrg",
					GitHubOAuthClientID:     "mockID",
					GitHubOAuthClientSecret: "mockSecret",
					WebhookSecret:           "",
					EnablePrivateRepo:       false,
					EncryptionKey:           "mockKey",
					EnterpriseBaseURL:       "",
					EnterpriseUploadURL:     "",
					EnableCodePreview:       "disable",
				})
			p.initializeAPI()
			p.SetAPI(&plugintest.API{})

			req := test.httpTest.CreateHTTPRequest(test.request)
			req.Header.Add("Mattermost-User-ID", test.userID)
			rr := httptest.NewRecorder()
			p.ServeHTTP(&plugin.Context{}, rr, req)
			test.httpTest.CompareHTTPResponse(rr, test.expectedResponse)
		})
	}
}

func TestGetToken(t *testing.T) {
	httpTestString := testutils.HTTPTest{
		T:       t,
		Encoder: testutils.EncodeString,
	}

	for name, test := range map[string]struct {
		httpTest         testutils.HTTPTest
		request          testutils.Request
		context          *plugin.Context
		expectedResponse testutils.ExpectedResponse
	}{
		"not authorized": {
			httpTest: httpTestString,
			request: testutils.Request{
				Method: http.MethodGet,
				URL:    "/api/v1/token",
				Body:   nil,
			},
			context: &plugin.Context{},
			expectedResponse: testutils.ExpectedResponse{
				StatusCode:   http.StatusUnauthorized,
				ResponseType: testutils.ContentTypePlain,
				Body:         "Not authorized\n",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin()
			p.setConfiguration(
				&Configuration{
					GitHubOrg:               "mockOrg",
					GitHubOAuthClientID:     "mockID",
					GitHubOAuthClientSecret: "mockSecret",
					EncryptionKey:           "mockKey",
				})
			p.initializeAPI()

			p.SetAPI(&plugintest.API{})

			req := test.httpTest.CreateHTTPRequest(test.request)
			rr := httptest.NewRecorder()

			p.ServeHTTP(test.context, rr, req)

			test.httpTest.CompareHTTPResponse(rr, test.expectedResponse)
		})
	}
}

func TestGetConfig(t *testing.T) {
	httpTestJSON := testutils.HTTPTest{
		T:       t,
		Encoder: testutils.EncodeJSON,
	}

	httpTestString := testutils.HTTPTest{
		T:       t,
		Encoder: testutils.EncodeString,
	}

	authorizedHeader := http.Header{}
	authorizedHeader.Add("Mattermost-Plugin-ID", "somePluginId")

	config := &Configuration{
		GitHubOrg:               "mockOrg",
		GitHubOAuthClientID:     "mockID",
		GitHubOAuthClientSecret: "mockSecret",
		EncryptionKey:           "mockKey",
	}

	for name, test := range map[string]struct {
		httpTest         testutils.HTTPTest
		request          testutils.Request
		expectedResponse testutils.ExpectedResponse
	}{
		"not authorized": {
			httpTest: httpTestString,
			request: testutils.Request{
				Method: http.MethodGet,
				URL:    "/api/v1/config",
				Body:   nil,
			},
			expectedResponse: testutils.ExpectedResponse{
				StatusCode:   http.StatusUnauthorized,
				ResponseType: testutils.ContentTypePlain,
				Body:         "Not authorized\n",
			},
		},
		"authorized": {
			httpTest: httpTestJSON,
			request: testutils.Request{
				Method: http.MethodGet,
				URL:    "/api/v1/config",
				Header: authorizedHeader,
				Body:   nil,
			},
			expectedResponse: testutils.ExpectedResponse{
				StatusCode:   http.StatusOK,
				ResponseType: testutils.ContentTypeJSON,
				Body:         config,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := NewPlugin()
			p.setConfiguration(config)
			p.initializeAPI()

			p.SetAPI(&plugintest.API{})

			req := test.httpTest.CreateHTTPRequest(test.request)
			rr := httptest.NewRecorder()

			p.ServeHTTP(&plugin.Context{}, rr, req)

			test.httpTest.CompareHTTPResponse(rr, test.expectedResponse)
		})
	}
}

type mockPluginAPI struct {
	Plugin
	mockOutputUserID    string
	mockOutputPostID    *model.Post
	mockOutputPermaLink string

	mockOutputGitHubClient *github.Client

	err error
}

type mockGithubClient struct {
	github.Client
}

type mockPosts struct {
	pluginapi.PostService
	err error
}

func (mpo *mockPosts) CreatePost(_ *model.Post) error {
	return mpo.err
}

type mockIssues struct {
	github.IssuesService
	mockIssue    *github.Issue
	mockResponse *github.Response
	mockEror     error
}

func (mi *mockIssues) Create(_ context.Context, _ string, _ string, _ *github.IssueRequest) (*github.Issue, *github.Response, error) {
	return mi.mockIssue, mi.mockResponse, mi.mockEror
}

func (mp *mockPluginAPI) writeAPIError(_ http.ResponseWriter, _ *APIErrorResponse) {
	return
}
func (mp *mockPluginAPI) getUsername(_ string) (string, error) {
	return mp.mockOutputUserID, mp.err
}
func (mp *mockPluginAPI) getPost(_ string) (*model.Post, error) {
	return mp.mockOutputPostID, mp.err
}
func (mp *mockPluginAPI) getPermaLink(_ string) string {
	return mp.mockOutputPermaLink
}

func (mp *mockPluginAPI) githubConnectUser(_ context.Context, _ *GitHubUserInfo) *github.Client {
	return mp.mockOutputGitHubClient
}

func TestCreateIssue(t *testing.T) {

}
