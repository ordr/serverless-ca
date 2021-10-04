all:
	GOOS=linux CGO_ENABLED=0 go build main.go
	zip function.zip main