#!/bin/sh

sleep 8

PEERS=""

for i in $(dig +yaml  filer | grep "IN A " | sed 's/.*IN A //'); do
	echo "IP: $i"
	if [ "$PEERS" != "" ]; then
		PEERS="${PEERS},"
	fi
	PEERS="${PEERS}${i}:8888"
done

echo "filer -master=master:9333 -port=8888 -peers=${PEERS}"

exec weed filer -master=master:9333 -port=8888 -peers=${PEERS}
