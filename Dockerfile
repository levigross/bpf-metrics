FROM golang:alpine as builder
RUN apk add --no-cache binutils git
RUN git clone https://github.com/levigross/ebpf-metrics.git
WORKDIR ebpf-metrics
ENV CGO_ENABLED=0
RUN go build -o /ebpf-metrics

FROM alpine:latest 
COPY --from=builder /ebpf-metrics .