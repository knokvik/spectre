FROM golang:1.22-alpine

WORKDIR /app

# Copy shared pkg first
COPY pkg/ ./pkg/

# Copy recon-engine source
COPY recon-engine/go.mod ./recon-engine/

COPY recon-engine/*.go ./recon-engine/

WORKDIR /app/recon-engine
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /recon-engine .

CMD ["/recon-engine"]
