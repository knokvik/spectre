FROM golang:1.22-alpine

WORKDIR /app

# Copy shared pkg first
COPY pkg/ ./pkg/

# Copy attack-orchestrator source
COPY attack-orchestrator/go.mod ./attack-orchestrator/
COPY attack-orchestrator/*.go ./attack-orchestrator/

WORKDIR /app/attack-orchestrator
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /attack-orchestrator .

CMD ["/attack-orchestrator"]
