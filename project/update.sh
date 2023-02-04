#!/bin/bash
echo "Updating repository"
git add .
git commit -a -m "New update"
git push origin master
echo "Updating repository finished"
