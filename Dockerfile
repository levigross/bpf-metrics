FROM golang:alpine as builder
RUN git clone https://github.com/levigross/ebpf-metrics.git
WORKDIR ebpf-metrics
ENV CGO_ENABLED=0
RUN go build

FROM alpine:latest 
COPY --from builder /ebpf-metrics/ebpf-metrics .