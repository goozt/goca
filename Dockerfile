FROM golang:1.25.8-alpine AS builder

WORKDIR /server/

RUN apk --no-cache add tzdata

RUN addgroup -S appgroup && adduser -S appuser -G appgroup -u 1000 -H -D

RUN mkdir -p /.rootCA /.ca && chown 1000:1000 /.rootCA /.ca

COPY . ./

RUN CGO_ENABLED=0 go build -o goca .

FROM scratch

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /server/goca /usr/bin/goca
COPY --from=builder --chown=1000:1000 /.rootCA /.rootCA
COPY --from=builder --chown=1000:1000 /.ca /.ca

ARG TZ=UTC
ENV TZ=$TZ
ENV ZONEINFO=/usr/share/zoneinfo

VOLUME [ "/.rootCA" ]
VOLUME [ "/.ca" ]

USER 1000

EXPOSE 8000
ENTRYPOINT [ "/usr/bin/goca", "-g", "-c", "-root", "/.rootCA" ]
