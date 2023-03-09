all:
	dotnet publish -c Release
	scp ./bin/Release/net6.0/linux-arm64/publish/* \
		biba@${DEBIAN}:~/Projects/rieki/
