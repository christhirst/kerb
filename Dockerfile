FROM golang:buster AS builder

RUN mkdir /app
COPY . /app
WORKDIR /app
RUN apk update && apk add --no-cache git
RUN go clean --modcache
RUN go get -d -v
RUN CGO_ENABLED=0 go build -o main

EXPOSE 8180 8280
CMD ["/app/main"]