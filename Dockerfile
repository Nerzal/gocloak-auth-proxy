FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gocloak-auth-proxy ./cmd/gocloak-auth-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gocloak-auth-proxy /gocloak-auth-proxy
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gocloak-auth-proxy"]
