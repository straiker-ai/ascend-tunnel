# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/ascend-tunnel ./cmd/ascend-tunnel \
 && sh scripts/third-party-notices.sh /out/THIRD_PARTY_NOTICES ./cmd/ascend-tunnel \
 && mkdir -p /out/state

# No shell, no package manager: the agent and the CA store, as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ascend-tunnel /usr/local/bin/ascend-tunnel
COPY --from=build /src/LICENSE /out/THIRD_PARTY_NOTICES /usr/share/doc/ascend-tunnel/
COPY --from=build --chown=65532:65532 /out/state /var/lib/ascend-tunnel
ENV TUNNEL_STATE_DIR=/var/lib/ascend-tunnel
VOLUME ["/var/lib/ascend-tunnel"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ascend-tunnel"]
