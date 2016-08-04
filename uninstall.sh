#!/bin/bash

sudo rm -rf /Library/Extensions/FlockFlock.kext
sudo rm -rf /Library/Application\ Support/FlockFlock
sudo rm -f /Library/LaunchDaemons/com.zdziarski.FlockFlock.plist
sudo rm -f ~/Library/LaunchAgents/com.zdziarski.FlockFlockUserAgent.plist
