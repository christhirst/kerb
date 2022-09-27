FROM golang:buster AS builder

RUN mkdir /app
COPY . /app
WORKDIR /app
RUN apt install vim
RUN apt update
RUN go clean --modcache
RUN go get -d -v
RUN CGO_ENABLED=0 go build -o main

EXPOSE 8180 8280
CMD ["/app/main"]
