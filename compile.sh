#!/bin/bash

gcc -g -lpthread server.c -o server

gcc -g client.c -o client
