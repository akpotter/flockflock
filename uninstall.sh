#!/bin/bash

sudo rm -rf /Library/Extensions/FlockFlock.kext
sudo rm -rf /Library/Application\ Support/FlockFlock
sudo rm -rf /Applications/FlockFlockUserAgent.app
sudo rm -f /Library/LaunchDaemons/com.zdziarski.FlockFlock.plist
sudo rm -f /Library/LaunchDaemons/com.zdziarski.FlockFlockDaemon.plist
sudo rm -f /Library/LaunchAgents/com.zdziarski.FlockFlockUserAgent.plist
sudo rm -rf /Library/FlockFlock
