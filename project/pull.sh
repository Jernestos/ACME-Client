#!/bin/bash
echo "Updating repository"
git pull origin master
cd project
./test_run
echo "Updating repository finished"
