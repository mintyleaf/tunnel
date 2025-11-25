package api

import (
	"net/http"
	"tunnel/pkg/ipam"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/swaggest/openapi-go/openapi3"
	"github.com/swaggest/rest/nethttp"
	"github.com/swaggest/rest/web"
	swgui "github.com/swaggest/swgui/v5emb"
	"github.com/swaggest/usecase"
	"github.com/swaggest/usecase/status"
)

type APIService struct {
	AuthService AuthService
	IPAMService ipam.IPAMService

	NebulaPublicAddr string

	CACert string
	CAKey  string
}

func NewAPIServer(
	authService AuthService,
	ipamService ipam.IPAMService,
	allowedOrigins []string,
	nebulaPubAddr, caCert, caKey string,
) *web.Service {
	svc := APIService{
		AuthService: authService,
		IPAMService: ipamService,

		NebulaPublicAddr: nebulaPubAddr,

		CACert: caCert,
		CAKey:  caKey,
	}

	webService := web.NewService(openapi3.NewReflector())

	// TODO: do this dynamically or idk
	webService.OpenAPISchema().SetTitle("Tunnel API")
	webService.OpenAPISchema().SetVersion("v0.0.1")

	// TODO: review this ok
	webService.Use(
		cors.Handler(
			cors.Options{
				AllowedOrigins:   allowedOrigins,
				AllowCredentials: true,
				AllowedHeaders: []string{
					"authorization",
					"content-type",
				},
				AllowedMethods: []string{
					"HEAD",
					"GET",
					"POST",
					"DELETE",
				},
			},
		),
	)

	webService.Wrap(
		middleware.Logger,
		middleware.Recoverer,
	)

	connectInteractor := usecase.NewInteractor(svc.ConnectGet)
	connectInteractor.SetTitle("Connect")
	connectInteractor.SetDescription("Requests a certificate for establishing a tunnel")
	connectInteractor.SetExpectedErrors(
		status.Internal,
		status.PermissionDenied,
	)
	webService.With(
		authService.MasterAuthMiddleware,
		authService.TokenAuthMiddleware,
	).Method(http.MethodGet, "/connect", nethttp.NewHandler(connectInteractor))

	tokenInteractor := usecase.NewInteractor(svc.TokenGet)
	tokenInteractor.SetTitle("One Time Token Request")
	tokenInteractor.SetDescription(
		"Requests a one time token (if enabled) to use it for certificate request. " +
			"Intended to be used within the localhost environment of the server.",
	)
	tokenInteractor.SetExpectedErrors(
		status.Internal,
		status.PermissionDenied,
	)
	webService.With(
		authService.MasterAuthMiddleware,
		authService.RequireAuthMiddleware,
	).Method(http.MethodGet, "/token", nethttp.NewHandler(tokenInteractor))

	webService.Docs("/docs", swgui.New)

	return webService
}
