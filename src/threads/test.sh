#!/bin/bash

#remove all result files
rm -rf build/tests/threads/*

							 declare -a testlist=(

#alarm tests
"alarm-multiple.result"
"alarm-negative.result"
"alarm.result"
"alarm-priority.result"
"alarm-simultaneous.result"
"alarm-single.result"
"alarm-wait.result"
"alarm-zero.result"

#priority tests
"priority-change.result"
"priority-condvar.result"
"priority-donate-chain.result"
"priority-donate-lower.result"
"priority-donate-multiple2.result"
"priority-donate-multiple.result"
"priority-donate-nest.result"
"priority-donate-one.result"
"priority-donate-sema.result"
"priority-fifo.result"
"priority-preempt.result"
"priority-sema.result"
)

for i in "${testlist[@]}"; do
make build/tests/threads/$i
done

egrep 'PASS|FAIL' build/tests/threads/priority*.result
egrep 'PASS|FAIL' build/tests/threads/alarm*.result
