#!/bin/bash

#remove the filesys
rm -rf filesys.dsk

pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos -p ../examples/echo -a echo -- -q
pintos -p ../examples/ls -a ls -- -q
pintos -q run 'echo x'
pintos -q run 'ls -lah .'
