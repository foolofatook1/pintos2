#!/bin/bash

#remove the filesys
rm -rf filesys.dsk

pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos -p ../examples/echo -a echo -- -q
pintos -p ../examples/ls -a ls -- -q
pintos -p ./build/tests/userprog/args-none -a args-none -- -q
pintos -p ./build/tests/userprog/args-single -a args-single -- -q
pintos -p ./build/tests/userprog/args-multiple -a args-multiple -- -q
pintos -p ~/Desktop/cmsc326/os/pintos2/src/examples/halt -a halt -- -q
pintos -p ./build/tests/userprog/exit -a exit -- -q
