FROM golang:1.22-alpine

WORKDIR /app

# Copy shared pkg first
COPY pkg/ ./pkg/

# Copy api-gateway source
COPY api-gateway/go.mod ./api-gateway/
COPY api-gateway/*.go ./api-gateway/
COPY api-gateway/templates/ ./api-gateway/templates/

WORKDIR /app/api-gateway
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /api-gateway .

EXPOSE 8080
CMD ["/api-gateway"]
