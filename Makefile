.PHONY: certs metadata

certs:
	openssl req -x509 -newkey rsa:2048 -keyout ./certs/myservice.key -out ./certs/myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

metadata:
	## need both servers running
	## we can upload to the test idp here https://samltest.id/upload.php
	curl localhost:8000/saml/metadata > ./metadata/sp-http-redirect-metadata.xml
	curl localhost:8001/saml/metadata > ./metadata/sp-http-post-metadata.xml

clean:
	rm certs/*
	rm metadata/*

redirect:
	go run ./cmd/sp-redirect/*.go

post:
	go run ./cmd/sp-post/*.go
