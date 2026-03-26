FROM golang:1.25.8-alpine AS builder

WORKDIR /server/

RUN apk --no-cache add tzdata

# Create a non-root user to embed in the scratch image.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup -u 1001 -H -D

COPY . ./

RUN CGO_ENABLED=0 go build -o goca .

FROM scratch

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /server/goca /usr/bin/goca

ARG TZ=UTC
ENV TZ=$TZ
ENV ZONEINFO=/usr/share/zoneinfo

# Run as non-root user (uid 1001).
USER 1001

VOLUME [ "/.rootCA" ]

EXPOSE 8000
ENTRYPOINT [ "/usr/bin/goca", "-g", "-c" ]
