#!/bin/bash

echo "$(cat $1)"==== | fold -w 4 | sed '$ d' | tr -d '\n' | base64 -d
