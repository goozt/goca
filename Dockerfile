FROM golang:1.25.8-alpine AS builder

WORKDIR /server/

RUN apk --no-cache add tzdata

COPY . ./

RUN CGO_ENABLED=0 go build -o goca .

FROM scratch

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /server/goca /usr/bin/goca

ARG TZ=UTC
ENV TZ=$TZ
ENV ZONEINFO=/usr/share/zoneinfo

VOLUME [ "/.rootCA" ]

EXPOSE 8000
ENTRYPOINT [ "/usr/bin/goca", "-g", "-c" ]