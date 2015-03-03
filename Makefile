all: bnotify bnotifyd bnotify-app

bnotify: proto-go
	cd bnotify && go build

bnotifyd: proto-go
	cd bnotifyd && go build

bnotify-app: proto-java
	cd bnotify-app && ./gradlew build

proto-go:
	cd proto && protoc bnotify.proto --go_out=plugins=grpc:.

proto-java:
	cd proto && protoc bnotify.proto --java_out=.
	cp -r proto/cc bnotify-app/app/src/main/java

clean:
	rm -f proto/bnotify.pb.go bnotifyd/bnotifyd bnotify/bnotify
	rm -rf proto/cc bnotify-app/app/src/main/java/cc/bran/bnotify/proto
	cd bnotify-app && ./gradlew clean