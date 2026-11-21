FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /gocloak-auth-proxy ./cmd/gocloak-auth-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gocloak-auth-proxy /gocloak-auth-proxy
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gocloak-auth-proxy"]
