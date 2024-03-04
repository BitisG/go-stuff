#!/bin/bash
set -e

echo "🔨 docker multiarch build for x86_64 + Apple Silicon"

echo "🔨 Building x64"
env GOOS=linux GOARCH=amd64 go build audit.go
docker buildx build --platform linux/amd64 -t bitisg/audit:v2_x64 --push .

echo "🔨 Building Arm"
env GOOS=linux GOARCH=arm64 go build audit.go
docker buildx build --platform linux/arm64 -t bitisg/audit:v2_arm --push .

echo "🔨 Creating manifest & pushing"
docker manifest create bitisg/audit:v2 bitisg/audit:v2_arm bitisg/audit:v2_x64
docker manifest push bitisg/audit:v2

echo "🔨 Cleaning"
docker rmi bitisg/audit:v2_x64 bitisg/audit:v2_arm

echo "✅ Done, remember to delete the _x64 and _arm tags from Hub"

