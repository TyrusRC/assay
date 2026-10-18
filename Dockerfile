FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /assay ./cmd/assay

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /assay /usr/local/bin/assay
ENTRYPOINT ["/usr/local/bin/assay"]
