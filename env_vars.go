package main

import "os"

var connString = string(os.Getenv("CONNSTR"))
var jwtKey = []byte(string(os.Getenv("SECRET")))
