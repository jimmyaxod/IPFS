#!/bin/bash

java -Xmx4G -Xms4G -cp target/ipfscrawl-1.0-SNAPSHOT-jar-with-dependencies.jar net.axod.ipfscrawl.Crawl --listen 127.0.0.1 4009
